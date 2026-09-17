"use strict";

module.exports = {
  id: "002_investigation_workspace",
  async up(c) {
    await c.query(`
      ALTER TABLE entities DROP CONSTRAINT entities_type_check;
      ALTER TABLE entities ADD CHECK (char_length(type) BETWEEN 1 AND 80);
      ALTER TABLE relationships DROP CONSTRAINT relationships_relationship_type_check;
      ALTER TABLE relationships ADD CHECK (char_length(relationship_type) BETWEEN 1 AND 80);
      ALTER TABLE relationships DROP CONSTRAINT relationships_epistemic_status_check;
      ALTER TABLE relationships ADD CHECK (epistemic_status IN ('FACT','INFERENCE','HYPOTHESIS'));
      ALTER TABLE relationships ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
      ALTER TABLE relationships ADD COLUMN created_by bigint;
      ALTER TABLE relationships ADD UNIQUE(id,investigation_id);
      UPDATE relationships SET created_at=first_observed_at;
      ALTER TABLE entities ADD COLUMN created_by bigint;
      ALTER TABLE observations ADD COLUMN epistemic_status text NOT NULL DEFAULT 'FACT' CHECK (epistemic_status IN ('FACT','INFERENCE','HYPOTHESIS'));
      CREATE TABLE workspace_records (
        id uuid PRIMARY KEY,
        investigation_id uuid NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        kind text NOT NULL CHECK (kind IN ('source','lead','note','layer','group')),
        data jsonb NOT NULL DEFAULT '{}',
        created_by bigint NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(),
        UNIQUE(id,investigation_id)
      );
      CREATE TABLE workspace_links (
        record_id uuid NOT NULL,
        investigation_id uuid NOT NULL,
        entity_id uuid,
        relationship_id uuid,
        lead_id uuid,
        FOREIGN KEY(record_id,investigation_id) REFERENCES workspace_records(id,investigation_id) ON DELETE CASCADE,
        FOREIGN KEY(entity_id,investigation_id) REFERENCES entities(id,investigation_id) ON DELETE CASCADE,
        FOREIGN KEY(relationship_id,investigation_id) REFERENCES relationships(id,investigation_id) ON DELETE CASCADE,
        FOREIGN KEY(lead_id,investigation_id) REFERENCES workspace_records(id,investigation_id) ON DELETE CASCADE,
        CHECK (num_nonnulls(entity_id,relationship_id,lead_id)=1)
      );
      CREATE UNIQUE INDEX workspace_links_unique ON workspace_links(record_id,entity_id,relationship_id,lead_id) NULLS NOT DISTINCT;
      CREATE INDEX workspace_records_case ON workspace_records(investigation_id,kind);
      CREATE INDEX workspace_links_case ON workspace_links(investigation_id);
      INSERT INTO workspace_records(id,investigation_id,kind,data,created_by,created_at)
        SELECT o.id,o.investigation_id,'source',jsonb_build_object('title','Imported observation · ' || o.collector,'url',o.source_url,'description','Preserved observation from the previous workspace','observed_at',o.observed_at,'epistemic_status',o.epistemic_status,'legacy_raw_data',o.raw_data),i.created_by,o.observed_at
        FROM observations o JOIN investigations i ON i.id=o.investigation_id WHERE o.source_url ~ '^https?://';
      INSERT INTO workspace_links(record_id,investigation_id,entity_id)
        SELECT o.id,o.investigation_id,o.entity_id FROM observations o JOIN workspace_records r ON r.id=o.id WHERE o.entity_id IS NOT NULL;
      INSERT INTO workspace_records(id,investigation_id,kind,data,created_by,created_at)
        SELECT e.id,r.investigation_id,'source',jsonb_build_object('title','Imported evidence · ' || e.collector,'url',e.source_url,'observed_at',e.observed_at,'epistemic_status',r.epistemic_status,'legacy_metadata',e.metadata),i.created_by,e.observed_at
        FROM relationship_evidence e JOIN relationships r ON r.id=e.relationship_id JOIN investigations i ON i.id=r.investigation_id WHERE e.source_url ~ '^https?://';
      INSERT INTO workspace_links(record_id,investigation_id,relationship_id)
        SELECT e.id,r.investigation_id,e.relationship_id FROM relationship_evidence e JOIN relationships r ON r.id=e.relationship_id JOIN workspace_records w ON w.id=e.id;
      CREATE TABLE evidence_files (
        source_id uuid PRIMARY KEY REFERENCES workspace_records(id) ON DELETE CASCADE,
        name text NOT NULL, mime text NOT NULL, content bytea NOT NULL,
        sha256 text NOT NULL
      );
    `);
  },
};
