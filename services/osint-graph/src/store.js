'use strict';

const { randomUUID } = require('crypto');
const { normalizeEntityInput, normalizeRelationshipInput, cleanText } = require('./security/validation');

function json(value) { return JSON.stringify(value ?? {}); }

class OsintStore {
  constructor(pool) { this.pool = pool; }

  async withTransaction(work) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async health() {
    const result = await this.pool.query('SELECT current_database() AS database, current_user AS user, NOW() AS now');
    return result.rows[0];
  }

  async audit(actorId, action, resourceType, resourceId = null, metadata = {}) {
    await this.pool.query(
      'INSERT INTO audit_logs (user_id, action, resource_type, resource_id, metadata) VALUES ($1,$2,$3,$4,$5::jsonb)',
      [actorId, action, resourceType, resourceId ? String(resourceId) : null, json(metadata)]
    );
  }

  async listInvestigations() {
    const result = await this.pool.query(`
      SELECT i.*,
        (SELECT COUNT(*)::int FROM entities e WHERE e.investigation_id = i.id) AS entity_count,
        (SELECT COUNT(*)::int FROM relationships r WHERE r.investigation_id = i.id) AS relationship_count
      FROM investigations i ORDER BY i.updated_at DESC, i.created_at DESC
    `);
    return result.rows;
  }

  async createInvestigation({ name, description = '', actorId }) {
    const id = randomUUID();
    const safeName = cleanText(name, { max: 160, required: true });
    const safeDescription = cleanText(description, { max: 2000 });
    const result = await this.pool.query(
      'INSERT INTO investigations (id,name,description,created_by) VALUES ($1,$2,$3,$4) RETURNING *',
      [id, safeName, safeDescription, actorId]
    );
    await this.audit(actorId, 'investigation.create', 'investigation', id, { name: safeName });
    return result.rows[0];
  }

  async getInvestigation(id) {
    const result = await this.pool.query('SELECT * FROM investigations WHERE id = $1', [id]);
    return result.rows[0] || null;
  }

  async deleteInvestigation(id, actorId) {
    const result = await this.pool.query('DELETE FROM investigations WHERE id = $1 RETURNING id, name', [id]);
    if (!result.rowCount) return null;
    await this.audit(actorId, 'investigation.delete', 'investigation', id, { deleted: true });
    return result.rows[0];
  }

  async ensureInvestigation(id, client = this.pool) {
    const result = await client.query('SELECT id FROM investigations WHERE id = $1', [id]);
    if (!result.rowCount) {
      const error = new Error('investigation_not_found');
      error.status = 404;
      throw error;
    }
  }

  async upsertEntity(client, investigationId, rawEntity) {
    const entity = normalizeEntityInput(rawEntity);
    const id = randomUUID();
    const result = await client.query(`
      INSERT INTO entities (id,investigation_id,type,canonical_name,display_name,metadata)
      VALUES ($1,$2,$3,$4,$5,$6::jsonb)
      ON CONFLICT (investigation_id,type,canonical_name) DO UPDATE SET
        display_name=EXCLUDED.display_name,
        metadata=entities.metadata || EXCLUDED.metadata,
        updated_at=NOW()
      RETURNING *
    `, [id, investigationId, entity.type, entity.canonicalName, entity.displayName, json(entity.metadata)]);
    const stored = result.rows[0];
    if (entity.platform && entity.username) {
      await client.query(`
        INSERT INTO social_accounts (
          id,investigation_id,entity_id,platform,username,profile_url,display_name,bio,avatar_url,followers_count,following_count,metadata,observed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,NOW())
        ON CONFLICT (investigation_id,platform,username) DO UPDATE SET
          entity_id=EXCLUDED.entity_id,
          profile_url=COALESCE(EXCLUDED.profile_url,social_accounts.profile_url),
          display_name=EXCLUDED.display_name,
          bio=COALESCE(NULLIF(EXCLUDED.bio,''),social_accounts.bio),
          avatar_url=COALESCE(EXCLUDED.avatar_url,social_accounts.avatar_url),
          followers_count=COALESCE(EXCLUDED.followers_count,social_accounts.followers_count),
          following_count=COALESCE(EXCLUDED.following_count,social_accounts.following_count),
          metadata=social_accounts.metadata || EXCLUDED.metadata,
          observed_at=NOW()
      `, [randomUUID(), investigationId, stored.id, entity.platform, entity.username, entity.profileUrl, entity.displayName, entity.bio || null,
        entity.metadata.avatar_url || null, entity.metadata.followers_count ?? null, entity.metadata.following_count ?? null, json(entity.metadata)]);
    }
    return { stored, normalized: entity };
  }

  async addEntity(investigationId, rawEntity, { actorId, collector = 'manual-entry' } = {}) {
    const result = await this.withTransaction(async (client) => {
      await this.ensureInvestigation(investigationId, client);
      const item = await this.upsertEntity(client, investigationId, rawEntity);
      const sourceUrl = item.normalized.profileUrl || `urn:studerria-osint:manual-entry:${item.stored.id}`;
      await client.query(`
        INSERT INTO observations (id,investigation_id,entity_id,source_type,source_url,collector,raw_data)
        VALUES ($1,$2,$3,'MANUAL',$4,$5,$6::jsonb)
      `, [randomUUID(), investigationId, item.stored.id, sourceUrl, collector, json({ type: item.normalized.type, canonical_name: item.normalized.canonicalName })]);
      await client.query('UPDATE investigations SET updated_at=NOW() WHERE id=$1', [investigationId]);
      return item.stored;
    });
    await this.audit(actorId, 'entity.create', 'entity', result.id, { investigation_id: investigationId, collector });
    return result;
  }

  async importDataset(investigationId, dataset, {
    actorId,
    collector = 'manual-import',
    maxNodes = 500,
    maxRelationships = 2000,
  } = {}) {
    const summary = await this.withTransaction(async (client) => {
      await this.ensureInvestigation(investigationId, client);
      const referenceMap = new Map();
      let entitiesCreatedOrUpdated = 0;
      for (const rawEntity of dataset.entities || []) {
        const item = await this.upsertEntity(client, investigationId, rawEntity);
        const references = [item.normalized.externalId, item.normalized.canonicalName, rawEntity.id, rawEntity.canonical_name].filter(Boolean).map(String);
        references.forEach((reference) => referenceMap.set(reference, item.stored.id));
        const sourceUrl = item.normalized.profileUrl || `urn:studerria-osint:${collector}:${item.stored.id}`;
        const observationId = randomUUID();
        await client.query(`
          INSERT INTO observations (id,investigation_id,entity_id,source_type,source_url,collector,raw_data)
          VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
        `, [observationId, investigationId, item.stored.id, collector === 'manual-import' ? 'MANUAL_IMPORT' : 'PUBLIC_SOURCE', sourceUrl, collector,
          json({ type: item.normalized.type, canonical_name: item.normalized.canonicalName })]);
        referenceMap.set(`observation:${item.normalized.externalId}`, observationId);
        entitiesCreatedOrUpdated += 1;
      }
      for (const rawObservation of dataset.observations || []) {
        const entityId = referenceMap.get(String(rawObservation.entity || '')) || null;
        if (!entityId) continue;
        const observationId = randomUUID();
        await client.query(`
          INSERT INTO observations (id,investigation_id,entity_id,source_type,source_url,collector,raw_data,observed_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,COALESCE($8::timestamptz,NOW()))
        `, [observationId, investigationId, entityId, cleanText(rawObservation.source_type || 'PUBLIC_SOURCE', { max: 80, required: true }),
          String(rawObservation.source_url || `urn:studerria-osint:${collector}:${entityId}`).slice(0, 2048), collector,
          json(rawObservation.raw_data || {}), rawObservation.observed_at || null]);
        referenceMap.set(`observation:${rawObservation.entity}`, observationId);
      }
      let relationshipsCreatedOrUpdated = 0;
      for (const rawRelationship of dataset.relationships || []) {
        const relationship = normalizeRelationshipInput(rawRelationship);
        const sourceId = referenceMap.get(relationship.source);
        const targetId = referenceMap.get(relationship.target);
        if (!sourceId || !targetId) throw new Error(`relationship_reference_missing:${relationship.source}:${relationship.target}`);
        const relationshipId = randomUUID();
        const inserted = await client.query(`
          INSERT INTO relationships (
            id,investigation_id,source_entity_id,target_entity_id,relationship_type,epistemic_status,weight,confidence,metadata
          ) VALUES ($1,$2,$3,$4,$5,'FACT',$6,$7,$8::jsonb)
          ON CONFLICT (investigation_id,source_entity_id,target_entity_id,relationship_type,epistemic_status) DO UPDATE SET
            weight=GREATEST(relationships.weight,EXCLUDED.weight),
            confidence=GREATEST(relationships.confidence,EXCLUDED.confidence),
            metadata=relationships.metadata || EXCLUDED.metadata,
            last_observed_at=NOW()
          RETURNING id
        `, [relationshipId, investigationId, sourceId, targetId, relationship.type, relationship.weight, relationship.confidence, json(relationship.metadata)]);
        const storedRelationshipId = inserted.rows[0].id;
        const sourceUrl = relationship.sourceUrl || `urn:studerria-osint:${collector}:${storedRelationshipId}`;
        await client.query(`
          INSERT INTO relationship_evidence (id,relationship_id,observation_id,source_type,source_url,collector,confidence,metadata)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
          ON CONFLICT (relationship_id,collector,source_url) DO UPDATE SET observed_at=NOW(), confidence=GREATEST(relationship_evidence.confidence,EXCLUDED.confidence)
        `, [randomUUID(), storedRelationshipId, referenceMap.get(`observation:${relationship.source}`) || null,
          collector === 'manual-import' ? 'MANUAL_IMPORT' : 'PUBLIC_SOURCE', sourceUrl, collector, relationship.confidence, json({})]);
        relationshipsCreatedOrUpdated += 1;
      }
      let interactionsCreated = 0;
      for (const rawInteraction of dataset.interactions || []) {
        const sourceId = referenceMap.get(String(rawInteraction.source));
        const targetId = referenceMap.get(String(rawInteraction.target));
        if (!sourceId || !targetId) continue;
        await client.query(`
          INSERT INTO interactions (id,investigation_id,source_entity_id,target_entity_id,type,source_url,happened_at,metadata)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
        `, [randomUUID(), investigationId, sourceId, targetId, cleanText(rawInteraction.type || 'PUBLIC_INTERACTION', { max: 80, required: true }),
          String(rawInteraction.source_url || `urn:studerria-osint:${collector}:interaction`).slice(0, 2048), rawInteraction.timestamp || null, json(rawInteraction.metadata || {})]);
        interactionsCreated += 1;
      }
      const counts = await client.query(`
        SELECT
          (SELECT COUNT(*)::int FROM entities WHERE investigation_id=$1) AS nodes,
          (SELECT COUNT(*)::int FROM relationships WHERE investigation_id=$1) AS relationships
      `, [investigationId]);
      if (counts.rows[0].nodes > maxNodes) throw new Error('graph_node_limit_exceeded');
      if (counts.rows[0].relationships > maxRelationships) throw new Error('graph_relationship_limit_exceeded');
      await client.query('UPDATE investigations SET updated_at=NOW() WHERE id=$1', [investigationId]);
      return {
        entities: entitiesCreatedOrUpdated,
        relationships: relationshipsCreatedOrUpdated,
        interactions: interactionsCreated,
        totalNodes: counts.rows[0].nodes,
        totalRelationships: counts.rows[0].relationships,
      };
    });
    await this.audit(actorId, 'investigation.import', 'investigation', investigationId, { collector, ...summary });
    return summary;
  }

  async getGraph(investigationId) {
    await this.ensureInvestigation(investigationId);
    const [entities, relationships, interactions] = await Promise.all([
      this.pool.query(`
        SELECT e.*, sa.platform, sa.username, sa.profile_url, sa.bio, sa.avatar_url,
          sa.followers_count, sa.following_count, sa.observed_at
        FROM entities e LEFT JOIN social_accounts sa ON sa.entity_id=e.id
        WHERE e.investigation_id=$1 ORDER BY e.created_at,e.id
      `, [investigationId]),
      this.pool.query(`
        SELECT r.*, COALESCE(jsonb_agg(jsonb_build_object(
          'source_type',re.source_type,'source_url',re.source_url,'collector',re.collector,
          'observed_at',re.observed_at,'confidence',re.confidence
        )) FILTER (WHERE re.id IS NOT NULL),'[]'::jsonb) AS evidence
        FROM relationships r LEFT JOIN relationship_evidence re ON re.relationship_id=r.id
        WHERE r.investigation_id=$1 GROUP BY r.id ORDER BY r.first_observed_at,r.id
      `, [investigationId]),
      this.pool.query('SELECT * FROM interactions WHERE investigation_id=$1 ORDER BY happened_at DESC NULLS LAST', [investigationId]),
    ]);
    return { entities: entities.rows, relationships: relationships.rows, interactions: interactions.rows };
  }

  async getEntity(investigationId, entityId) {
    const entityResult = await this.pool.query(`
      SELECT e.*,sa.platform,sa.username,sa.profile_url,sa.bio,sa.avatar_url,sa.followers_count,sa.following_count,sa.observed_at
      FROM entities e LEFT JOIN social_accounts sa ON sa.entity_id=e.id
      WHERE e.investigation_id=$1 AND e.id=$2
    `, [investigationId, entityId]);
    if (!entityResult.rowCount) return null;
    const [relationships, observations] = await Promise.all([
      this.pool.query(`
        SELECT r.*, src.display_name AS source_name, dst.display_name AS target_name,
          COALESCE(jsonb_agg(jsonb_build_object('source_url',re.source_url,'collector',re.collector,'observed_at',re.observed_at,'confidence',re.confidence)) FILTER (WHERE re.id IS NOT NULL),'[]'::jsonb) evidence
        FROM relationships r JOIN entities src ON src.id=r.source_entity_id JOIN entities dst ON dst.id=r.target_entity_id
        LEFT JOIN relationship_evidence re ON re.relationship_id=r.id
        WHERE r.investigation_id=$1 AND (r.source_entity_id=$2 OR r.target_entity_id=$2)
        GROUP BY r.id,src.display_name,dst.display_name ORDER BY r.confidence DESC,r.weight DESC
      `, [investigationId, entityId]),
      this.pool.query(`SELECT id,source_type,source_url,collector,observed_at,raw_data FROM observations WHERE investigation_id=$1 AND entity_id=$2 ORDER BY observed_at DESC LIMIT 100`, [investigationId, entityId]),
    ]);
    return { ...entityResult.rows[0], relationships: relationships.rows, observations: observations.rows };
  }

  async createRun({ investigationId, kind, collector = null, parameters = {}, actorId }) {
    await this.ensureInvestigation(investigationId);
    const id = randomUUID();
    const result = await this.pool.query(`
      INSERT INTO analysis_runs (id,investigation_id,kind,status,collector,parameters,created_by)
      VALUES ($1,$2,$3,'queued',$4,$5::jsonb,$6) RETURNING *
    `, [id, investigationId, kind, collector, json(parameters), actorId]);
    await this.audit(actorId, 'run.queue', 'analysis_run', id, {
      investigation_id: investigationId,
      kind,
      collector,
      target: parameters.username || parameters.url || null,
    });
    return result.rows[0];
  }

  async startRun(id) {
    const result = await this.pool.query("UPDATE analysis_runs SET status='running',started_at=NOW(),error=NULL WHERE id=$1 AND status='queued' RETURNING *", [id]);
    return result.rows[0] || null;
  }

  async finishRun(id, result) {
    const row = await this.pool.query("UPDATE analysis_runs SET status='completed',finished_at=NOW(),result=$2::jsonb WHERE id=$1 RETURNING *", [id, json(result)]);
    return row.rows[0] || null;
  }

  async failRun(id, error) {
    const message = cleanText(error?.message || error || 'run_failed', { max: 1000 }) || 'run_failed';
    const row = await this.pool.query("UPDATE analysis_runs SET status='failed',finished_at=NOW(),error=$2 WHERE id=$1 RETURNING *", [id, message]);
    return row.rows[0] || null;
  }

  async getRun(investigationId, id) {
    const result = await this.pool.query('SELECT * FROM analysis_runs WHERE investigation_id=$1 AND id=$2', [investigationId, id]);
    return result.rows[0] || null;
  }

  async recoverInterruptedRuns() {
    const result = await this.pool.query(`
      UPDATE analysis_runs SET status='failed',finished_at=NOW(),error='service_restarted_before_completion'
      WHERE status IN ('queued','running') RETURNING id
    `);
    return result.rowCount;
  }

  async saveFindings(investigationId, runId, findings) {
    await this.withTransaction(async (client) => {
      await client.query('DELETE FROM analysis_findings WHERE analysis_run_id=$1', [runId]);
      for (const finding of findings) {
        await client.query(`
          INSERT INTO analysis_findings (id,investigation_id,analysis_run_id,finding_type,title,explanation,confidence,entity_ids,input_relationship_ids,metadata)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8::uuid[],$9::uuid[],$10::jsonb)
        `, [randomUUID(), investigationId, runId, finding.type, finding.title, finding.explanation, finding.confidence ?? null,
          finding.entityIds || [], finding.inputRelationshipIds || [], json(finding.metadata || {})]);
      }
    });
  }

  async listFindings(investigationId) {
    const result = await this.pool.query('SELECT * FROM analysis_findings WHERE investigation_id=$1 ORDER BY created_at DESC', [investigationId]);
    return result.rows;
  }

  async purgeExpired(retentionDays) {
    const result = await this.pool.query("DELETE FROM investigations WHERE updated_at < NOW() - ($1::text || ' days')::interval RETURNING id", [retentionDays]);
    return result.rowCount;
  }
}

module.exports = { OsintStore };
