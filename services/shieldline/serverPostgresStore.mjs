import { randomUUID } from "node:crypto";
import pg from "pg";
import { createClient } from "redis";
import { simulateMission } from "./serverGame.mjs";
import { calculateDefenseBonus, stableHash } from "./src/game/simulationCore.mjs";

const { Pool } = pg;
const CAMPAIGN_MISSIONS = [
  { id: "campaign-night-01", title: "Night 01: Signal Window" },
  { id: "campaign-night-02", title: "Night 02: Blackout Relay" },
  { id: "campaign-night-03", title: "Night 03: Last Reserve" },
];

export const SHIELDLINE_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS shieldline_users (
  id text PRIMARY KEY,
  platform text NOT NULL DEFAULT 'web',
  display_name text NOT NULL DEFAULT 'Commander',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS shieldline_sessions (
  token_hash text PRIMARY KEY,
  actor_id text NOT NULL REFERENCES shieldline_users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  rotated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS shieldline_cities (
  id text PRIMARY KEY,
  actor_id text NOT NULL UNIQUE REFERENCES shieldline_users(id) ON DELETE CASCADE,
  name text NOT NULL DEFAULT 'Campaign City',
  revision integer NOT NULL DEFAULT 1,
  state jsonb NOT NULL DEFAULT '{}'::jsonb,
  import_id text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS shieldline_assets (
  id text PRIMARY KEY,
  city_id text NOT NULL REFERENCES shieldline_cities(id) ON DELETE CASCADE,
  actor_id text NOT NULL REFERENCES shieldline_users(id) ON DELETE CASCADE,
  kind text NOT NULL,
  assigned_city_id text NOT NULL,
  readiness numeric(5,2) NOT NULL,
  position jsonb,
  state jsonb NOT NULL DEFAULT '{}'::jsonb,
  import_id text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shieldline_assets_city_idx ON shieldline_assets(city_id, kind);
ALTER TABLE shieldline_cities ADD COLUMN IF NOT EXISTS import_id text;
ALTER TABLE shieldline_assets ADD COLUMN IF NOT EXISTS import_id text;
CREATE INDEX IF NOT EXISTS shieldline_sessions_actor_idx ON shieldline_sessions(actor_id, expires_at DESC);
CREATE TABLE IF NOT EXISTS shieldline_runs (
  id text PRIMARY KEY,
  actor_id text NOT NULL REFERENCES shieldline_users(id),
  mission_id text NOT NULL,
  source text NOT NULL,
  seed text NOT NULL,
  sim_version text NOT NULL,
  status text NOT NULL,
  result text NOT NULL,
  revision integer NOT NULL DEFAULT 1,
  started_at timestamptz NOT NULL,
  completed_at timestamptz NOT NULL,
  plan jsonb NOT NULL DEFAULT '{}'::jsonb,
  summary jsonb NOT NULL,
  run_document jsonb NOT NULL,
  import_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shieldline_runs_actor_created_idx ON shieldline_runs(actor_id, created_at DESC);
CREATE TABLE IF NOT EXISTS shieldline_sim_events (
  run_id text NOT NULL REFERENCES shieldline_runs(id) ON DELETE CASCADE,
  sequence integer NOT NULL,
  event_id text NOT NULL UNIQUE,
  tick bigint NOT NULL,
  type text NOT NULL,
  sim_version text NOT NULL,
  actor_id text,
  asset_id text,
  target_id text,
  payload jsonb NOT NULL,
  event_document jsonb NOT NULL,
  PRIMARY KEY (run_id, sequence)
);
CREATE INDEX IF NOT EXISTS shieldline_sim_events_type_idx ON shieldline_sim_events(type, tick);
CREATE TABLE IF NOT EXISTS shieldline_snapshots (
  run_id text NOT NULL REFERENCES shieldline_runs(id) ON DELETE CASCADE,
  sequence integer NOT NULL,
  tick bigint NOT NULL,
  sim_version text NOT NULL,
  state jsonb NOT NULL,
  snapshot_document jsonb NOT NULL,
  PRIMARY KEY (run_id, sequence)
);
CREATE TABLE IF NOT EXISTS shieldline_commands (
  run_id text NOT NULL REFERENCES shieldline_runs(id) ON DELETE CASCADE,
  command_id text NOT NULL,
  actor_id text NOT NULL,
  revision integer NOT NULL,
  scope jsonb NOT NULL,
  type text NOT NULL,
  payload jsonb NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT now(),
  command_document jsonb NOT NULL,
  PRIMARY KEY (run_id, command_id)
);
CREATE TABLE IF NOT EXISTS shieldline_campaigns (
  actor_id text PRIMARY KEY REFERENCES shieldline_users(id),
  current_mission_id text,
  completed_mission_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_run_id text REFERENCES shieldline_runs(id),
  revision integer NOT NULL DEFAULT 1,
  import_id text,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS shieldline_outbox (
  id text PRIMARY KEY,
  actor_id text REFERENCES shieldline_users(id),
  type text NOT NULL,
  payload jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  available_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  import_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shieldline_outbox_pending_idx ON shieldline_outbox(available_at) WHERE delivered_at IS NULL;
CREATE TABLE IF NOT EXISTS shieldline_campaign_projection (
  actor_id text PRIMARY KEY REFERENCES shieldline_users(id),
  current_mission_id text,
  completed_mission_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
  last_run_id text,
  last_result text,
  interceptions integer NOT NULL DEFAULT 0,
  impacts integer NOT NULL DEFAULT 0,
  revision integer NOT NULL DEFAULT 1,
  projected_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS shieldline_import_jobs (
  id text PRIMARY KEY,
  checksum text NOT NULL UNIQUE,
  source_file text NOT NULL,
  backup_file text,
  status text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE TABLE IF NOT EXISTS shieldline_audit_log (
  id bigserial PRIMARY KEY,
  actor_id text,
  method text NOT NULL,
  path text NOT NULL,
  reason text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shieldline_audit_log_created_idx ON shieldline_audit_log(created_at DESC);
CREATE TABLE IF NOT EXISTS shieldline_analytics_events (
  id bigserial PRIMARY KEY,
  actor_id text,
  event_name text NOT NULL,
  channel text NOT NULL,
  session_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  properties jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shieldline_analytics_event_time_idx ON shieldline_analytics_events(event_name, occurred_at DESC);
`;

export async function ensureShieldlineSchema(pool) {
  await pool.query(SHIELDLINE_SCHEMA_SQL);
}

function defaultProgress() {
  return { currentMissionId: CAMPAIGN_MISSIONS[0].id, completedMissionIds: [], lastRunId: null, revision: 1 };
}

function progressView(progress) {
  return {
    currentMissionId: progress.currentMissionId,
    completedMissionIds: progress.completedMissionIds,
    lastRunId: progress.lastRunId,
    missions: CAMPAIGN_MISSIONS.map((mission, index) => ({
      ...mission,
      index: index + 1,
      status: progress.completedMissionIds.includes(mission.id) ? "completed" : progress.currentMissionId === mission.id ? "active" : "locked",
    })),
  };
}

async function upsertUser(client, actorId) {
  const platform = actorId.startsWith("tg-") ? "telegram" : actorId.startsWith("guest-") ? "guest" : "web";
  await client.query(
    `INSERT INTO shieldline_users (id, platform, display_name) VALUES ($1, $2, $3)
     ON CONFLICT (id) DO UPDATE SET platform = EXCLUDED.platform, updated_at = now()`,
    [actorId, platform, actorId === "web-commander" ? "Web Commander" : actorId],
  );
}

async function readCachedRun(redis, runId) {
  if (!redis?.isReady) return null;
  try { const value = await redis.get(`shieldline:run:${runId}`); return value ? JSON.parse(value) : null; } catch { return null; }
}

async function cacheRun(redis, run) {
  if (!redis?.isReady) return;
  try { await redis.setEx(`shieldline:run:${run.id}`, 3600, JSON.stringify(run)); } catch { /* PostgreSQL remains authoritative. */ }
}

async function persistCampaignRun(pool, redis, run, { actorId, source, plan }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await upsertUser(client, actorId);
    const cityId = `campaign-city-${stableHash(actorId)}`;
    await client.query(
      `INSERT INTO shieldline_cities (id, actor_id, state) VALUES ($1,$2,$3::jsonb)
       ON CONFLICT (actor_id) DO UPDATE SET revision = shieldline_cities.revision + 1, state = EXCLUDED.state, updated_at = now()`,
      [cityId, actorId, JSON.stringify({ missionId: run.missionId, lastRunId: run.id, result: run.result })],
    );
    const activeAssetIds = [];
    for (const [index, asset] of (plan?.assets || []).entries()) {
      const assetId = String(asset.id || `${cityId}-asset-${index + 1}`).slice(0, 120);
      activeAssetIds.push(assetId);
      await client.query(
        `INSERT INTO shieldline_assets (id, city_id, actor_id, kind, assigned_city_id, readiness, position, state)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb)
         ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind, assigned_city_id = EXCLUDED.assigned_city_id, readiness = EXCLUDED.readiness, position = EXCLUDED.position, state = EXCLUDED.state, updated_at = now()`,
        [assetId, cityId, actorId, asset.kind, asset.cityId, asset.readiness, JSON.stringify(asset.position || null), JSON.stringify({ source: "campaign-plan", runId: run.id })],
      );
    }
    if (activeAssetIds.length) await client.query("DELETE FROM shieldline_assets WHERE city_id = $1 AND NOT (id = ANY($2::text[]))", [cityId, activeAssetIds]);
    const inserted = await client.query(
      `INSERT INTO shieldline_runs
       (id, actor_id, mission_id, source, seed, sim_version, status, result, revision, started_at, completed_at, plan, summary, run_document)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14::jsonb)
       ON CONFLICT (id) DO NOTHING RETURNING id`,
      [run.id, actorId, run.missionId, source, run.seed, run.simVersion, run.status || "completed", run.result, run.revision || 1, run.startedAt, run.completedAt, JSON.stringify(plan || {}), JSON.stringify({ interceptions: run.interceptions, impacts: run.impacts, ammoSpent: run.ammoSpent, sectorSummary: run.sectorSummary }), JSON.stringify(run)],
    );
    if (inserted.rowCount) {
      for (const entry of run.events) {
        await client.query(
          `INSERT INTO shieldline_sim_events (run_id, sequence, event_id, tick, type, sim_version, actor_id, asset_id, target_id, payload, event_document)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb)`,
          [run.id, entry.sequence, entry.id, entry.tick ?? entry.occurredAtMs, entry.type, entry.simVersion || run.simVersion, actorId, entry.assetId || null, entry.targetId || null, JSON.stringify(entry.payload || {}), JSON.stringify(entry)],
        );
      }
      for (const snapshot of run.snapshots || []) {
        await client.query(
          `INSERT INTO shieldline_snapshots (run_id, sequence, tick, sim_version, state, snapshot_document) VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb)`,
          [run.id, snapshot.sequence, snapshot.tick, snapshot.simVersion, JSON.stringify(snapshot.state), JSON.stringify(snapshot)],
        );
      }
      if (source === "campaign") {
        const existing = await client.query("SELECT current_mission_id, completed_mission_ids, last_run_id, revision FROM shieldline_campaigns WHERE actor_id = $1 FOR UPDATE", [actorId]);
        const progress = existing.rowCount ? {
          currentMissionId: existing.rows[0].current_mission_id,
          completedMissionIds: existing.rows[0].completed_mission_ids || [],
          lastRunId: existing.rows[0].last_run_id,
          revision: existing.rows[0].revision,
        } : defaultProgress();
        if (progress.currentMissionId === run.missionId && run.result !== "setback") {
          progress.completedMissionIds = [...new Set([...progress.completedMissionIds, run.missionId])];
          const index = CAMPAIGN_MISSIONS.findIndex((mission) => mission.id === run.missionId);
          progress.currentMissionId = CAMPAIGN_MISSIONS[index + 1]?.id || null;
        }
        progress.lastRunId = run.id;
        await client.query(
          `INSERT INTO shieldline_campaigns (actor_id, current_mission_id, completed_mission_ids, last_run_id, revision)
           VALUES ($1,$2,$3::jsonb,$4,$5)
           ON CONFLICT (actor_id) DO UPDATE SET current_mission_id = EXCLUDED.current_mission_id, completed_mission_ids = EXCLUDED.completed_mission_ids, last_run_id = EXCLUDED.last_run_id, revision = shieldline_campaigns.revision + 1, updated_at = now()`,
          [actorId, progress.currentMissionId, JSON.stringify(progress.completedMissionIds), progress.lastRunId, progress.revision + 1],
        );
      }
    }
    await client.query("COMMIT");
    await cacheRun(redis, run);
    return run;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function createPostgresGameStore({ legacyStore, pool, redis = null }) {
  await ensureShieldlineSchema(pool);
  return {
    ...legacyStore,
    storageDriver: "postgres",
    async runMission(seed, actorId = "web-commander", plan = {}, missionId = CAMPAIGN_MISSIONS[0].id, source = "campaign") {
      if (source !== "campaign") return legacyStore.runMission(seed, actorId, plan, missionId, source);
      const run = simulateMission(seed, new Date().toISOString(), calculateDefenseBonus(plan), missionId);
      return persistCampaignRun(pool, redis, run, { actorId, source, plan });
    },
    async getRun(runId) {
      const cached = await readCachedRun(redis, runId);
      if (cached) return cached;
      const result = await pool.query("SELECT run_document FROM shieldline_runs WHERE id = $1", [runId]);
      if (!result.rowCount) return legacyStore.getRun(runId);
      const run = result.rows[0].run_document;
      await cacheRun(redis, run);
      return run;
    },
    async getRunEvents(runId, after = 0) {
      const result = await pool.query("SELECT event_document FROM shieldline_sim_events WHERE run_id = $1 AND sequence > $2 ORDER BY sequence", [runId, after]);
      if (result.rowCount) return result.rows.map((row) => row.event_document);
      return legacyStore.getRunEvents(runId, after);
    },
    async getRunSnapshots(runId, tick = Number.POSITIVE_INFINITY) {
      const safeTick = Number.isFinite(tick) ? tick : Number.MAX_SAFE_INTEGER;
      const result = await pool.query("SELECT snapshot_document FROM shieldline_snapshots WHERE run_id = $1 AND tick <= $2 ORDER BY sequence", [runId, safeTick]);
      if (result.rowCount) return result.rows.map((row) => row.snapshot_document);
      return legacyStore.getRunSnapshots(runId, tick);
    },
    async appendOperationCommand(runId, actorId, input = {}) {
      const commandId = String(input.commandId || "").slice(0, 96);
      if (!commandId) throw new Error("commandId is required.");
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const runResult = await client.query("SELECT revision FROM shieldline_runs WHERE id = $1 FOR UPDATE", [runId]);
        if (!runResult.rowCount) {
          await client.query("ROLLBACK");
          return legacyStore.appendOperationCommand(runId, actorId, input);
        }
        const duplicate = await client.query("SELECT command_document FROM shieldline_commands WHERE run_id = $1 AND command_id = $2", [runId, commandId]);
        const revision = runResult.rows[0].revision;
        if (duplicate.rowCount) {
          await client.query("COMMIT");
          return { command: duplicate.rows[0].command_document, revision, duplicate: true };
        }
        if (Number(input.baseRevision) !== revision) {
          const latest = await client.query("SELECT command_document FROM shieldline_commands WHERE run_id = $1 ORDER BY revision DESC LIMIT 20", [runId]);
          throw Object.assign(new Error("Operation revision conflict."), { statusCode: 409, latestPatch: { revision, commands: latest.rows.map((row) => row.command_document) } });
        }
        await upsertUser(client, actorId);
        const command = { commandId, runId, actorId, revision: revision + 1, scope: input.scope || { type: "operation" }, type: String(input.type || "unknown").slice(0, 64), payload: input.payload || {}, acceptedAt: new Date().toISOString() };
        await client.query(
          `INSERT INTO shieldline_commands (run_id, command_id, actor_id, revision, scope, type, payload, command_document)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7::jsonb,$8::jsonb)`,
          [runId, commandId, actorId, revision + 1, JSON.stringify(command.scope), command.type, JSON.stringify(command.payload), JSON.stringify(command)],
        );
        await client.query("UPDATE shieldline_runs SET revision = $2, run_document = jsonb_set(run_document, '{revision}', to_jsonb($2::integer)) WHERE id = $1", [runId, revision + 1]);
        await client.query("COMMIT");
        if (redis?.isReady) await redis.del(`shieldline:run:${runId}`).catch(() => undefined);
        return { command, revision: revision + 1, duplicate: false };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally { client.release(); }
    },
    async recordCampaignCommand(actorId, type, payload = {}) {
      await upsertUser(pool, actorId);
      const progress = await this.campaignState(actorId);
      if (!progress.lastRunId) return legacyStore.recordCampaignCommand(actorId, type, payload);
      const revisionResult = await pool.query("SELECT revision FROM shieldline_runs WHERE id = $1", [progress.lastRunId]);
      if (!revisionResult.rowCount) return legacyStore.recordCampaignCommand(actorId, type, payload);
      return this.appendOperationCommand(progress.lastRunId, actorId, { commandId: randomUUID(), baseRevision: revisionResult.rows[0].revision, scope: { type: "operation" }, type, payload });
    },
    async campaignState(actorId = "web-commander") {
      const result = await pool.query("SELECT current_mission_id, completed_mission_ids, last_run_id, revision FROM shieldline_campaigns WHERE actor_id = $1", [actorId]);
      if (!result.rowCount) return progressView(defaultProgress());
      return progressView({ currentMissionId: result.rows[0].current_mission_id, completedMissionIds: result.rows[0].completed_mission_ids || [], lastRunId: result.rows[0].last_run_id, revision: result.rows[0].revision });
    },
    async createSession(tokenHash, actorId, expiresAt) {
      await upsertUser(pool, actorId);
      await pool.query("INSERT INTO shieldline_sessions (token_hash, actor_id, expires_at) VALUES ($1,$2,$3) ON CONFLICT (token_hash) DO UPDATE SET actor_id = EXCLUDED.actor_id, expires_at = EXCLUDED.expires_at, rotated_at = now(), revoked_at = NULL", [tokenHash, actorId, expiresAt]);
      if (redis?.isReady) {
        const ttl = Math.max(1, Math.floor((new Date(expiresAt).getTime() - Date.now()) / 1000));
        await redis.setEx(`shieldline:session:${tokenHash}`, ttl, JSON.stringify({ actorId, expiresAt, rotatedAt: new Date().toISOString() })).catch(() => undefined);
      }
    },
    async findSession(tokenHash) {
      if (redis?.isReady) {
        const cached = await redis.get(`shieldline:session:${tokenHash}`).catch(() => null);
        if (cached) return JSON.parse(cached);
      }
      const result = await pool.query("SELECT actor_id, expires_at, rotated_at FROM shieldline_sessions WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()", [tokenHash]);
      if (!result.rowCount) return null;
      const session = { actorId: result.rows[0].actor_id, expiresAt: result.rows[0].expires_at.toISOString(), rotatedAt: result.rows[0].rotated_at.toISOString() };
      if (redis?.isReady) {
        const ttl = Math.max(1, Math.floor((new Date(session.expiresAt).getTime() - Date.now()) / 1000));
        await redis.setEx(`shieldline:session:${tokenHash}`, ttl, JSON.stringify(session)).catch(() => undefined);
      }
      return session;
    },
    async revokeSession(tokenHash) {
      await pool.query("UPDATE shieldline_sessions SET revoked_at = now() WHERE token_hash = $1", [tokenHash]);
      if (redis?.isReady) await redis.del(`shieldline:session:${tokenHash}`).catch(() => undefined);
    },
    async revokeActorSessions(actorId) {
      const hashes = await pool.query("UPDATE shieldline_sessions SET revoked_at = now() WHERE actor_id = $1 AND revoked_at IS NULL RETURNING token_hash", [actorId]);
      if (redis?.isReady && hashes.rowCount) await redis.del(hashes.rows.map((row) => `shieldline:session:${row.token_hash}`)).catch(() => undefined);
    },
    async auditRejectedCommand({ actorId = null, method, path, reason, details = {} }) {
      await pool.query("INSERT INTO shieldline_audit_log (actor_id, method, path, reason, details) VALUES ($1,$2,$3,$4,$5::jsonb)", [actorId, method, path, reason, JSON.stringify(details)]);
    },
    async recordAnalytics(actorId, event) {
      await pool.query("INSERT INTO shieldline_analytics_events (actor_id, event_name, channel, session_id, occurred_at, properties) VALUES ($1,$2,$3,$4,$5,$6::jsonb)", [actorId, event.eventName, event.channel, event.sessionId, event.occurredAt, JSON.stringify(event.properties || {})]);
    },
    async health() {
      await pool.query("SELECT 1");
      return { storage: "postgres", redis: redis?.isReady ? "ready" : "unavailable" };
    },
  };
}

export async function createConfiguredPostgresStore({ legacyStore, env = process.env }) {
  const pool = new Pool({
    host: env.SHIELDLINE_DB_HOST || "db",
    port: Number(env.SHIELDLINE_DB_PORT || 5432),
    user: env.SHIELDLINE_DB_USER,
    password: env.SHIELDLINE_DB_PASSWORD,
    database: env.SHIELDLINE_DB_NAME,
    max: Number(env.SHIELDLINE_DB_POOL_MAX || 10),
    connectionTimeoutMillis: Number(env.SHIELDLINE_DB_CONNECT_TIMEOUT_MS || 5_000),
  });
  let redis = null;
  if (env.SHIELDLINE_REDIS_URL) {
    redis = createClient({ url: env.SHIELDLINE_REDIS_URL });
    redis.on("error", (error) => console.error(JSON.stringify({ level: "error", component: "shieldline.redis", message: error.message })));
    await redis.connect().catch(() => undefined);
  }
  return createPostgresGameStore({ legacyStore, pool, redis });
}
