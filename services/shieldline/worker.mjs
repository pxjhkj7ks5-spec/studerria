import pg from "pg";
import { ensureShieldlineSchema } from "./serverPostgresStore.mjs";

const { Pool } = pg;
const role = process.env.SHIELDLINE_WORKER_ROLE || "projection";
const intervalMs = Math.max(1_000, Number(process.env.SHIELDLINE_WORKER_INTERVAL_MS || 10_000));
const runOnce = process.env.SHIELDLINE_WORKER_RUN_ONCE === "true";
const telegramBotToken = process.env.SHIELDLINE_TELEGRAM_BOT_TOKEN || "";
const pool = new Pool({
  host: process.env.SHIELDLINE_DB_HOST || "db",
  port: Number(process.env.SHIELDLINE_DB_PORT || 5432),
  user: process.env.SHIELDLINE_DB_USER,
  password: process.env.SHIELDLINE_DB_PASSWORD,
  database: process.env.SHIELDLINE_DB_NAME,
  max: Number(process.env.SHIELDLINE_DB_POOL_MAX || 4),
});

function log(level, message, fields = {}) {
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, service: "shieldline-worker", role, message, ...fields }));
}

async function rebuildCampaignProjection() {
  await pool.query(`
    INSERT INTO shieldline_campaign_projection
      (actor_id, current_mission_id, completed_mission_ids, last_run_id, last_result, interceptions, impacts, revision, projected_at)
    SELECT c.actor_id, c.current_mission_id, c.completed_mission_ids, c.last_run_id,
      r.result,
      COALESCE((r.summary->>'interceptions')::integer, 0),
      COALESCE((r.summary->>'impacts')::integer, 0),
      c.revision,
      now()
    FROM shieldline_campaigns c
    LEFT JOIN shieldline_runs r ON r.id = c.last_run_id
    ON CONFLICT (actor_id) DO UPDATE SET
      current_mission_id = EXCLUDED.current_mission_id,
      completed_mission_ids = EXCLUDED.completed_mission_ids,
      last_run_id = EXCLUDED.last_run_id,
      last_result = EXCLUDED.last_result,
      interceptions = EXCLUDED.interceptions,
      impacts = EXCLUDED.impacts,
      revision = EXCLUDED.revision,
      projected_at = now()
  `);
  const result = await pool.query("SELECT count(*)::integer AS count FROM shieldline_campaign_projection");
  log("info", "campaign projection rebuilt", { rows: result.rows[0].count });
}

async function deliverOutbox() {
  if (!telegramBotToken) {
    log("info", "notification delivery skipped; Telegram token is not configured");
    return;
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const pending = await client.query(
      `SELECT o.id, o.actor_id, o.type, o.payload, o.attempts, p.chat_id, i.provider_user_id AS telegram_id FROM shieldline_outbox o
       LEFT JOIN shieldline_notification_preferences p ON p.actor_id = o.actor_id AND p.enabled = true
       LEFT JOIN shieldline_identities i ON i.actor_id = o.actor_id AND i.provider = 'telegram'
       WHERE o.delivered_at IS NULL AND o.available_at <= now()
       ORDER BY o.created_at LIMIT 20 FOR UPDATE OF o SKIP LOCKED`,
    );
    for (const item of pending.rows) {
      const chatId = item.type === "admin.test" ? item.telegram_id : item.chat_id || (item.actor_id?.startsWith("tg-") ? item.actor_id.slice(3) : null);
      if (!chatId) {
        await client.query("UPDATE shieldline_outbox SET delivered_at = now(), attempts = attempts + 1 WHERE id = $1", [item.id]);
        continue;
      }
      const text = item.payload?.text || (item.type === "campaign.report.ready" ? "Shieldline: campaign report is ready." : "Shieldline: command update is ready.");
      const response = await fetch(`https://api.telegram.org/bot${telegramBotToken}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: chatId, text }),
      }).catch(() => null);
      if (response?.ok) await client.query("UPDATE shieldline_outbox SET delivered_at = now(), attempts = attempts + 1 WHERE id = $1", [item.id]);
      else await client.query("UPDATE shieldline_outbox SET attempts = attempts + 1, available_at = now() + make_interval(secs => LEAST(3600, 30 * power(2, attempts))) WHERE id = $1", [item.id]);
    }
    await client.query(`UPDATE shieldline_admin_broadcasts b SET
      delivered_count = stats.delivered,
      failed_count = stats.failed,
      status = CASE WHEN stats.pending = 0 THEN 'completed' ELSE 'sending' END,
      completed_at = CASE WHEN stats.pending = 0 THEN COALESCE(b.completed_at, now()) ELSE NULL END
      FROM (
        SELECT payload->>'broadcastId' AS id,
          count(*) FILTER (WHERE delivered_at IS NOT NULL)::integer AS delivered,
          count(*) FILTER (WHERE delivered_at IS NULL AND attempts >= 5)::integer AS failed,
          count(*) FILTER (WHERE delivered_at IS NULL AND attempts < 5)::integer AS pending
        FROM shieldline_outbox WHERE type = 'admin.broadcast' GROUP BY payload->>'broadcastId'
      ) stats WHERE b.id = stats.id`);
    await client.query("COMMIT");
    log("info", "notification outbox processed", { rows: pending.rowCount });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally { client.release(); }
}

async function runWorker() {
  if (role === "projection") await rebuildCampaignProjection();
  else if (role === "notification") await deliverOutbox();
  else throw new Error(`Unknown Shieldline worker role: ${role}`);
  await pool.query(`INSERT INTO shieldline_worker_heartbeats (role, status, details) VALUES ($1,'ready',$2::jsonb)
    ON CONFLICT (role) DO UPDATE SET status = EXCLUDED.status, details = EXCLUDED.details, updated_at = now()`, [role, JSON.stringify({ intervalMs })]);
}

let stopping = false;
async function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log("info", "worker stopping", { signal });
  await pool.end();
  process.exit(0);
}
process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
process.on("SIGINT", () => { void shutdown("SIGINT"); });

await ensureShieldlineSchema(pool);
log("info", "worker started", { intervalMs, runOnce });
do {
  const started = Date.now();
  await runWorker().catch((error) => log("error", "worker cycle failed", { error: error.message }));
  if (runOnce) break;
  await new Promise((resolve) => setTimeout(resolve, Math.max(250, intervalMs - (Date.now() - started))));
} while (!stopping);
await pool.end();
