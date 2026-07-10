import { createHash, randomUUID } from "node:crypto";
import { copyFile, readFile } from "node:fs/promises";
import pg from "pg";
import { ensureShieldlineSchema } from "../serverPostgresStore.mjs";
import { stableHash } from "../src/game/simulationCore.mjs";

const { Pool } = pg;
const args = new Set(process.argv.slice(2));
const rollbackIndex = process.argv.indexOf("--rollback");
const rollbackId = rollbackIndex >= 0 ? process.argv[rollbackIndex + 1] : null;
const sourceFile = process.env.SHIELDLINE_GAME_STORE_FILE || "/data/game-store.json";
const pool = new Pool({
  host: process.env.SHIELDLINE_DB_HOST || "db",
  port: Number(process.env.SHIELDLINE_DB_PORT || 5432),
  user: process.env.SHIELDLINE_DB_USER,
  password: process.env.SHIELDLINE_DB_PASSWORD,
  database: process.env.SHIELDLINE_DB_NAME,
  max: 2,
});

function counts(store) {
  return {
    runs: Object.keys(store.runs || {}).length,
    events: Object.values(store.runs || {}).reduce((sum, run) => sum + (run.events?.length || 0), 0),
    snapshots: Object.values(store.runs || {}).reduce((sum, run) => sum + (run.snapshots?.length || 0), 0),
    campaigns: Object.keys(store.campaigns || {}).length,
    outbox: (store.notificationOutbox || []).length,
  };
}

async function ensureUser(client, actorId) {
  await client.query("INSERT INTO shieldline_users (id, platform, display_name) VALUES ($1,$2,$3) ON CONFLICT (id) DO NOTHING", [actorId, actorId.startsWith("tg-") ? "telegram" : "web", actorId]);
}

async function rollback(importId) {
  if (!importId) throw new Error("--rollback requires an import id.");
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM shieldline_outbox WHERE import_id = $1", [importId]);
    await client.query("DELETE FROM shieldline_campaigns WHERE import_id = $1", [importId]);
    await client.query("DELETE FROM shieldline_runs WHERE import_id = $1", [importId]);
    await client.query("DELETE FROM shieldline_assets WHERE import_id = $1", [importId]);
    await client.query("DELETE FROM shieldline_cities WHERE import_id = $1", [importId]);
    const updated = await client.query("UPDATE shieldline_import_jobs SET status = 'rolled_back', completed_at = now() WHERE id = $1 RETURNING backup_file", [importId]);
    if (!updated.rowCount) throw new Error(`Import ${importId} was not found.`);
    await client.query("COMMIT");
    console.log(JSON.stringify({ ok: true, importId, status: "rolled_back", backupFile: updated.rows[0].backup_file }));
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

async function applyImport(store, checksum, source) {
  const existing = await pool.query("SELECT id, status, backup_file FROM shieldline_import_jobs WHERE checksum = $1", [checksum]);
  if (existing.rowCount && existing.rows[0].status === "completed") {
    console.log(JSON.stringify({ ok: true, idempotent: true, importId: existing.rows[0].id, backupFile: existing.rows[0].backup_file }));
    return;
  }
  const importId = randomUUID();
  const backupFile = `${source}.backup-${importId}.json`;
  await copyFile(source, backupFile);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("INSERT INTO shieldline_import_jobs (id, checksum, source_file, backup_file, status, details) VALUES ($1,$2,$3,$4,'running',$5::jsonb)", [importId, checksum, source, backupFile, JSON.stringify(counts(store))]);
    for (const run of Object.values(store.runs || {})) {
      const actorId = run.metadata?.actorId || "web-commander";
      await ensureUser(client, actorId);
      const cityId = `campaign-city-${stableHash(actorId)}`;
      await client.query("INSERT INTO shieldline_cities (id, actor_id, state, import_id) VALUES ($1,$2,$3::jsonb,$4) ON CONFLICT (actor_id) DO NOTHING", [cityId, actorId, JSON.stringify({ importedRunId: run.id }), importId]);
      for (const [index, asset] of (run.metadata?.plan?.assets || []).entries()) {
        await client.query(
          `INSERT INTO shieldline_assets (id, city_id, actor_id, kind, assigned_city_id, readiness, position, state, import_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9) ON CONFLICT (id) DO NOTHING`,
          [String(asset.id || `${cityId}-asset-${index + 1}`), cityId, actorId, asset.kind, asset.cityId || "unknown", asset.readiness || 0, JSON.stringify(asset.position || null), JSON.stringify({ imported: true, importId }), importId],
        );
      }
      await client.query(
        `INSERT INTO shieldline_runs (id, actor_id, mission_id, source, seed, sim_version, status, result, revision, started_at, completed_at, plan, summary, run_document, import_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::jsonb,$14::jsonb,$15)
         ON CONFLICT (id) DO NOTHING`,
        [run.id, actorId, run.missionId || "campaign-night-01", run.metadata?.source || "campaign", run.seed || run.id, run.simVersion || "legacy", run.status || "completed", run.result || "contained", run.revision || 1, run.startedAt || new Date(0).toISOString(), run.completedAt || run.startedAt || new Date(0).toISOString(), JSON.stringify(run.metadata?.plan || {}), JSON.stringify({ interceptions: run.interceptions || 0, impacts: run.impacts || 0, ammoSpent: run.ammoSpent || 0, sectorSummary: run.sectorSummary || {} }), JSON.stringify(run), importId],
      );
      for (const event of run.events || []) {
        await client.query(
          `INSERT INTO shieldline_sim_events (run_id, sequence, event_id, tick, type, sim_version, actor_id, asset_id, target_id, payload, event_document)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11::jsonb) ON CONFLICT DO NOTHING`,
          [run.id, event.sequence, event.id, event.tick ?? event.occurredAtMs ?? 0, event.type, event.simVersion || run.simVersion || "legacy", actorId, event.assetId || null, event.targetId || null, JSON.stringify(event.payload || {}), JSON.stringify(event)],
        );
      }
      for (const snapshot of run.snapshots || []) {
        await client.query(
          `INSERT INTO shieldline_snapshots (run_id, sequence, tick, sim_version, state, snapshot_document)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb) ON CONFLICT DO NOTHING`,
          [run.id, snapshot.sequence, snapshot.tick, snapshot.simVersion || run.simVersion || "legacy", JSON.stringify(snapshot.state || {}), JSON.stringify(snapshot)],
        );
      }
    }
    for (const [actorId, campaign] of Object.entries(store.campaigns || {})) {
      await ensureUser(client, actorId);
      await client.query(
        `INSERT INTO shieldline_campaigns (actor_id, current_mission_id, completed_mission_ids, last_run_id, revision, import_id)
         VALUES ($1,$2,$3::jsonb,$4,$5,$6) ON CONFLICT (actor_id) DO NOTHING`,
        [actorId, campaign.currentMissionId || null, JSON.stringify(campaign.completedMissionIds || []), campaign.lastRunId || null, campaign.revision || 1, importId],
      );
    }
    for (const item of store.notificationOutbox || []) {
      const actorId = item.actorId || null;
      if (actorId) await ensureUser(client, actorId);
      await client.query(
        `INSERT INTO shieldline_outbox (id, actor_id, type, payload, import_id, created_at)
         VALUES ($1,$2,$3,$4::jsonb,$5,$6) ON CONFLICT (id) DO NOTHING`,
        [item.id, actorId, item.type, JSON.stringify(item.payload || {}), importId, item.createdAt || new Date().toISOString()],
      );
    }
    await client.query("UPDATE shieldline_import_jobs SET status = 'completed', completed_at = now() WHERE id = $1", [importId]);
    await client.query("COMMIT");
    console.log(JSON.stringify({ ok: true, importId, checksum, backupFile, imported: counts(store) }));
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

try {
  await ensureShieldlineSchema(pool);
  if (rollbackId) await rollback(rollbackId);
  else {
    const source = await readFile(sourceFile);
    const checksum = createHash("sha256").update(source).digest("hex");
    const store = JSON.parse(source.toString("utf8"));
    if (!args.has("--apply")) console.log(JSON.stringify({ ok: true, dryRun: true, sourceFile, checksum, found: counts(store) }));
    else await applyImport(store, checksum, sourceFile);
  }
} finally {
  await pool.end();
}
