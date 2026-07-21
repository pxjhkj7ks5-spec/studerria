import { randomBytes, randomUUID } from "node:crypto";
import pg from "pg";
import { ensureShieldlineSchema } from "./serverPostgresStore.mjs";
import { hashSessionToken } from "./serverSecurity.mjs";

const { Pool } = pg;

export const SHIELDLINE_ADMIN_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS shieldline_admin_sessions (
  token_hash text PRIMARY KEY,
  csrf_hash text NOT NULL,
  admin_label text NOT NULL DEFAULT 'owner',
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shieldline_admin_sessions_expiry_idx ON shieldline_admin_sessions(expires_at) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS shieldline_admin_audit_log (
  id bigserial PRIMARY KEY,
  source text NOT NULL,
  admin_label text NOT NULL,
  admin_telegram_id text,
  action text NOT NULL,
  target_actor_id text,
  reason text NOT NULL,
  before_state jsonb,
  after_state jsonb,
  request_id text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS shieldline_admin_audit_created_idx ON shieldline_admin_audit_log(created_at DESC);
CREATE TABLE IF NOT EXISTS shieldline_admin_actions (
  token_hash text PRIMARY KEY,
  admin_telegram_id text NOT NULL,
  action text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  step integer NOT NULL DEFAULT 1,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS shieldline_bot_updates (
  update_id bigint PRIMARY KEY,
  status text NOT NULL DEFAULT 'processing',
  processed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS shieldline_admin_broadcasts (
  id text PRIMARY KEY,
  admin_label text NOT NULL,
  text text NOT NULL,
  audience jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'draft',
  recipient_count integer NOT NULL DEFAULT 0,
  queued_count integer NOT NULL DEFAULT 0,
  delivered_count integer NOT NULL DEFAULT 0,
  failed_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  queued_at timestamptz,
  completed_at timestamptz
);
CREATE TABLE IF NOT EXISTS shieldline_worker_heartbeats (
  role text PRIMARY KEY,
  status text NOT NULL DEFAULT 'ready',
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);
`;

function iso(value) {
  return value?.toISOString?.() || value || null;
}

function userView(row) {
  if (!row) return null;
  return {
    id: row.id,
    nickname: row.nickname,
    displayName: row.nickname || row.display_name,
    platform: row.platform,
    status: row.status || "active",
    suspensionReason: row.suspension_reason || null,
    suspendedAt: iso(row.suspended_at),
    createdAt: iso(row.created_at),
    lastSeenAt: iso(row.last_seen_at),
    lastLoginAt: iso(row.last_login_at),
    registrationCompletedAt: iso(row.registration_completed_at),
    consentVersion: row.consent_version,
    consentAcceptedAt: iso(row.consent_accepted_at),
    adminNote: row.admin_note || "",
    telegram: row.telegram_id ? { id: row.telegram_id, ...(row.telegram_profile || {}) } : null,
    deviceCount: Number(row.device_count || 0),
    sessionCount: Number(row.session_count || 0),
    operationCount: Number(row.operation_count || 0),
  };
}

async function audit(client, actor, action, targetActorId, reason, beforeState, afterState, requestId = null) {
  await client.query(
    `INSERT INTO shieldline_admin_audit_log
      (source, admin_label, admin_telegram_id, action, target_actor_id, reason, before_state, after_state, request_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9)`,
    [actor.source, actor.label, actor.telegramId || null, action, targetActorId || null, reason, beforeState ? JSON.stringify(beforeState) : null, afterState ? JSON.stringify(afterState) : null, requestId],
  );
}

const USER_SELECT = `
SELECT u.*,
  i.provider_user_id AS telegram_id, i.profile AS telegram_profile,
  COALESCE(d.device_count, 0) AS device_count,
  COALESCE(s.session_count, 0) AS session_count,
  COALESCE(r.operation_count, 0) AS operation_count
FROM shieldline_users u
LEFT JOIN shieldline_identities i ON i.actor_id = u.id AND i.provider = 'telegram'
LEFT JOIN (SELECT actor_id, count(*) AS device_count FROM shieldline_devices WHERE revoked_at IS NULL GROUP BY actor_id) d ON d.actor_id = u.id
LEFT JOIN (SELECT actor_id, count(*) AS session_count FROM shieldline_sessions WHERE revoked_at IS NULL AND expires_at > now() GROUP BY actor_id) s ON s.actor_id = u.id
LEFT JOIN (SELECT actor_id, count(*) AS operation_count FROM shieldline_runs GROUP BY actor_id) r ON r.actor_id = u.id`;

export async function createAdminStore({ pool, ensureBaseSchema = true }) {
  if (ensureBaseSchema) await ensureShieldlineSchema(pool);
  await pool.query(SHIELDLINE_ADMIN_SCHEMA_SQL);

  async function getUser(actorId) {
    const result = await pool.query(`${USER_SELECT} WHERE u.id = $1`, [actorId]);
    return userView(result.rows[0]);
  }

  async function resolveUser(value) {
    const query = String(value || "").trim().replace(/^@/, "");
    if (!query) return null;
    const result = await pool.query(
      `${USER_SELECT}
       WHERE u.id = $1 OR lower(COALESCE(u.nickname, '')) = lower($1)
         OR i.provider_user_id = $1 OR lower(COALESCE(i.profile->>'username', '')) = lower($1)
       ORDER BY CASE WHEN u.id = $1 THEN 0 WHEN lower(COALESCE(u.nickname, '')) = lower($1) THEN 1 ELSE 2 END LIMIT 1`,
      [query],
    );
    return userView(result.rows[0]);
  }

  async function mutateUser(actor, actorId, action, reason, callback, requestId = null) {
    if (!String(reason || "").trim()) throw Object.assign(new Error("Вкажіть причину зміни."), { statusCode: 400 });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT id FROM shieldline_users WHERE id = $1 FOR UPDATE", [actorId]);
      const beforeResult = await client.query(`${USER_SELECT} WHERE u.id = $1`, [actorId]);
      if (!beforeResult.rowCount) throw Object.assign(new Error("Користувача не знайдено."), { statusCode: 404 });
      const before = userView(beforeResult.rows[0]);
      await callback(client, before);
      const afterResult = await client.query(`${USER_SELECT} WHERE u.id = $1`, [actorId]);
      const after = userView(afterResult.rows[0]);
      await audit(client, actor, action, actorId, String(reason).trim(), before, after, requestId);
      await client.query("COMMIT");
      return after;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally { client.release(); }
  }

  return {
    pool,
    async createSession(adminLabel, ttlSeconds = 28_800) {
      const token = randomBytes(32).toString("base64url");
      const csrf = randomBytes(24).toString("base64url");
      const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
      await pool.query("INSERT INTO shieldline_admin_sessions (token_hash, csrf_hash, admin_label, expires_at) VALUES ($1,$2,$3,$4)", [hashSessionToken(token), hashSessionToken(csrf), adminLabel, expiresAt]);
      return { token, csrf, expiresAt: expiresAt.toISOString(), adminLabel };
    },
    async verifySession(token, csrf = null) {
      if (!/^[A-Za-z0-9_-]{32,128}$/.test(String(token || ""))) return null;
      const result = await pool.query(
        `UPDATE shieldline_admin_sessions SET last_seen_at = now()
         WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
         RETURNING admin_label, csrf_hash, expires_at`,
        [hashSessionToken(token)],
      );
      if (!result.rowCount) return null;
      if (csrf !== null && hashSessionToken(csrf) !== result.rows[0].csrf_hash) return null;
      return { source: "web", label: result.rows[0].admin_label, expiresAt: iso(result.rows[0].expires_at) };
    },
    async revokeSession(token) {
      await pool.query("UPDATE shieldline_admin_sessions SET revoked_at = now() WHERE token_hash = $1", [hashSessionToken(token)]);
    },
    async dashboard() {
      const result = await pool.query(`SELECT
        (SELECT count(*) FROM shieldline_users) AS users,
        (SELECT count(*) FROM shieldline_users WHERE created_at >= now() - interval '7 days') AS new_users,
        (SELECT count(*) FROM shieldline_users WHERE last_seen_at >= now() - interval '24 hours') AS active_users,
        (SELECT count(*) FROM shieldline_users WHERE status = 'suspended') AS suspended_users,
        (SELECT count(*) FROM shieldline_identities WHERE provider = 'telegram') AS telegram_users,
        (SELECT count(*) FROM shieldline_runs WHERE created_at >= now() - interval '24 hours') AS operations,
        (SELECT count(*) FROM shieldline_outbox WHERE delivered_at IS NULL) AS pending_notifications`);
      return Object.fromEntries(Object.entries(result.rows[0]).map(([key, value]) => [key, Number(value)]));
    },
    async listUsers({ query = "", status = "", telegram = "", activity = "", cursor = "", limit = 50 } = {}) {
      const safeLimit = Math.max(1, Math.min(100, Number(limit) || 50));
      const values = [String(query).trim(), status, telegram, cursor, safeLimit + 1, activity];
      const result = await pool.query(
        `${USER_SELECT}
         WHERE ($1 = '' OR u.id ILIKE '%' || $1 || '%' OR COALESCE(u.nickname, '') ILIKE '%' || $1 || '%'
           OR i.provider_user_id ILIKE '%' || $1 || '%' OR COALESCE(i.profile->>'username', '') ILIKE '%' || $1 || '%')
           AND ($2 = '' OR u.status = $2)
           AND ($3 = '' OR ($3 = 'linked' AND i.provider_user_id IS NOT NULL) OR ($3 = 'unlinked' AND i.provider_user_id IS NULL))
           AND ($4 = '' OR u.id > $4)
           AND ($6 = '' OR ($6 = 'day' AND u.last_seen_at >= now() - interval '24 hours') OR ($6 = 'week' AND u.last_seen_at >= now() - interval '7 days') OR ($6 = 'inactive' AND (u.last_seen_at IS NULL OR u.last_seen_at < now() - interval '30 days')))
         ORDER BY u.id LIMIT $5`, values);
      const rows = result.rows.map(userView);
      const hasMore = rows.length > safeLimit;
      return { items: rows.slice(0, safeLimit), nextCursor: hasMore ? rows[safeLimit - 1].id : null };
    },
    getUser,
    resolveUser,
    async userDetails(actorId) {
      const user = await getUser(actorId);
      if (!user) return null;
      const [devices, sessions, operations, history] = await Promise.all([
        pool.query("SELECT id, platform, first_seen_at, last_seen_at, revoked_at FROM shieldline_devices WHERE actor_id = $1 ORDER BY last_seen_at DESC LIMIT 50", [actorId]),
        pool.query("SELECT expires_at, rotated_at, revoked_at, created_at FROM shieldline_sessions WHERE actor_id = $1 ORDER BY created_at DESC LIMIT 50", [actorId]),
        pool.query("SELECT id, mission_id, source, status, result, started_at, completed_at, summary, created_at FROM shieldline_runs WHERE actor_id = $1 ORDER BY created_at DESC LIMIT 50", [actorId]),
        pool.query("SELECT id, source, admin_label, action, reason, created_at FROM shieldline_admin_audit_log WHERE target_actor_id = $1 ORDER BY created_at DESC LIMIT 50", [actorId]),
      ]);
      return { user, devices: devices.rows, sessions: sessions.rows, operations: operations.rows, audit: history.rows };
    },
    async listOperations({ cursor = "", limit = 50 } = {}) {
      const result = await pool.query(
        `SELECT r.id, r.actor_id, u.nickname, r.mission_id, r.source, r.status, r.result, r.started_at, r.completed_at, r.summary, r.created_at
         FROM shieldline_runs r LEFT JOIN shieldline_users u ON u.id = r.actor_id
         WHERE ($1 = '' OR r.id < $1) ORDER BY r.id DESC LIMIT $2`,
        [cursor, Math.max(1, Math.min(100, Number(limit) || 50))],
      );
      return { items: result.rows, nextCursor: result.rows.length ? result.rows.at(-1).id : null };
    },
    async operationDetails(runId) {
      const run = await pool.query("SELECT id, actor_id, mission_id, source, status, result, started_at, completed_at, summary, revision, created_at FROM shieldline_runs WHERE id = $1", [runId]);
      if (!run.rowCount) return null;
      const events = await pool.query("SELECT sequence, event_id, tick, type, actor_id, asset_id, target_id, payload FROM shieldline_sim_events WHERE run_id = $1 ORDER BY sequence LIMIT 500", [runId]);
      return { operation: run.rows[0], events: events.rows };
    },
    async listAudit(limit = 100) {
      return (await pool.query("SELECT * FROM shieldline_admin_audit_log ORDER BY created_at DESC LIMIT $1", [Math.max(1, Math.min(200, Number(limit) || 100))])).rows;
    },
    async systemHealth() {
      const db = await pool.query("SELECT now() AS checked_at, current_database() AS database");
      const queues = await pool.query("SELECT count(*) FILTER (WHERE delivered_at IS NULL)::integer AS pending, count(*) FILTER (WHERE delivered_at IS NOT NULL)::integer AS delivered FROM shieldline_outbox");
      const workers = await pool.query("SELECT role, status, details, updated_at, updated_at >= now() - interval '2 minutes' AS online FROM shieldline_worker_heartbeats ORDER BY role");
      return { database: "ready", checkedAt: iso(db.rows[0].checked_at), databaseName: db.rows[0].database, outbox: queues.rows[0], workers: workers.rows };
    },
    suspend(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.suspend", reason, (client) => client.query("UPDATE shieldline_users SET status = 'suspended', suspended_at = now(), suspension_reason = $2, updated_at = now() WHERE id = $1", [actorId, reason]), requestId);
    },
    activate(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.activate", reason, (client) => client.query("UPDATE shieldline_users SET status = 'active', suspended_at = NULL, suspension_reason = NULL, updated_at = now() WHERE id = $1", [actorId]), requestId);
    },
    revokeSessions(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.revoke_sessions", reason, (client) => client.query("UPDATE shieldline_sessions SET revoked_at = now() WHERE actor_id = $1 AND revoked_at IS NULL", [actorId]), requestId);
    },
    revokeDevices(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.revoke_devices", reason, (client) => client.query("UPDATE shieldline_devices SET revoked_at = now() WHERE actor_id = $1 AND revoked_at IS NULL", [actorId]), requestId);
    },
    resetConsent(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.reset_consent", reason, (client) => client.query("UPDATE shieldline_users SET consent_version = NULL, consent_accepted_at = NULL, updated_at = now() WHERE id = $1", [actorId]), requestId);
    },
    unlinkTelegram(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.unlink_telegram", reason, async (client) => { await client.query("DELETE FROM shieldline_identities WHERE actor_id = $1 AND provider = 'telegram'", [actorId]); await client.query("DELETE FROM shieldline_notification_preferences WHERE actor_id = $1", [actorId]); }, requestId);
    },
    updateNote(actor, actorId, note, reason, requestId) {
      return mutateUser(actor, actorId, "user.update_note", reason, (client) => client.query("UPDATE shieldline_users SET admin_note = $2, updated_at = now() WHERE id = $1", [actorId, String(note || "").slice(0, 2000)]), requestId);
    },
    resetProgress(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.reset_progress", reason, async (client) => {
        await client.query("DELETE FROM shieldline_player_progress WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_campaign_projection WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_campaigns WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_cities WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_runs WHERE actor_id = $1", [actorId]);
      }, requestId);
    },
    anonymize(actor, actorId, reason, requestId) {
      return mutateUser(actor, actorId, "user.anonymize", reason, async (client) => {
        const anonymous = `deleted-${actorId.replace(/[^a-z0-9]/gi, "").slice(-8).toLowerCase() || "user"}-${randomUUID().slice(0, 6)}`;
        await client.query("DELETE FROM shieldline_identities WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_notification_preferences WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_transfer_codes WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_sessions WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_devices WHERE actor_id = $1", [actorId]);
        await client.query(`UPDATE shieldline_users SET nickname = $2, nickname_normalized = $2, display_name = $2, platform = 'anonymized', status = 'anonymized', suspension_reason = NULL, admin_note = NULL, consent_version = NULL, consent_accepted_at = NULL, updated_at = now() WHERE id = $1`, [actorId, anonymous]);
      }, requestId);
    },
    async deleteUser(actor, actorId, confirmation, reason, requestId) {
      const before = await getUser(actorId);
      if (!before) throw Object.assign(new Error("Користувача не знайдено."), { statusCode: 404 });
      if (![before.id, before.nickname].filter(Boolean).includes(String(confirmation || "").trim())) throw Object.assign(new Error("Підтвердження не збігається з nickname або actor ID."), { statusCode: 409 });
      if (!String(reason || "").trim()) throw Object.assign(new Error("Вкажіть причину видалення."), { statusCode: 400 });
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query("DELETE FROM shieldline_campaign_projection WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_campaigns WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_outbox WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_cities WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_runs WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_analytics_events WHERE actor_id = $1", [actorId]);
        await client.query("DELETE FROM shieldline_users WHERE id = $1", [actorId]);
        await audit(client, actor, "user.delete", actorId, reason, before, null, requestId);
        await client.query("COMMIT");
        return { deleted: true, actorId };
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally { client.release(); }
    },
    async previewBroadcast() {
      const result = await pool.query(`SELECT count(*)::integer AS count FROM shieldline_users u
        JOIN shieldline_notification_preferences p ON p.actor_id = u.id AND p.enabled = true
        JOIN shieldline_identities i ON i.actor_id = u.id AND i.provider = 'telegram'
        WHERE u.status = 'active'`);
      return { recipientCount: Number(result.rows[0].count) };
    },
    async queueBroadcast(actor, text, reason = "Адміністративна розсилка", requestId = null) {
      const message = String(text || "").trim();
      if (!message || message.length > 3500) throw Object.assign(new Error("Повідомлення має містити від 1 до 3500 символів."), { statusCode: 400 });
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const recipients = await client.query(`SELECT u.id FROM shieldline_users u
          JOIN shieldline_notification_preferences p ON p.actor_id = u.id AND p.enabled = true
          JOIN shieldline_identities i ON i.actor_id = u.id AND i.provider = 'telegram' WHERE u.status = 'active'`);
        const broadcastId = randomUUID();
        await client.query("INSERT INTO shieldline_admin_broadcasts (id, admin_label, text, audience, status, recipient_count, queued_count, queued_at) VALUES ($1,$2,$3,$4::jsonb,'queued',$5,$5,now())", [broadcastId, actor.label, message, JSON.stringify({ status: "active", telegram: true, notifications: true }), recipients.rowCount]);
        for (const row of recipients.rows) await client.query("INSERT INTO shieldline_outbox (id, actor_id, type, payload) VALUES ($1,$2,'admin.broadcast',$3::jsonb)", [randomUUID(), row.id, JSON.stringify({ text: message, broadcastId })]);
        await audit(client, actor, "broadcast.queue", null, reason, null, { broadcastId, recipientCount: recipients.rowCount }, requestId);
        await client.query("COMMIT");
        return { id: broadcastId, recipientCount: recipients.rowCount, status: "queued" };
      } catch (error) { await client.query("ROLLBACK").catch(() => undefined); throw error; } finally { client.release(); }
    },
    async queueTestNotification(actor, target, text, reason = "Тестове повідомлення", requestId = null) {
      const user = await resolveUser(target);
      if (!user?.telegram?.id) throw Object.assign(new Error("Користувача з Telegram-прив’язкою не знайдено."), { statusCode: 404 });
      const message = String(text || "").trim();
      if (!message || message.length > 3500) throw Object.assign(new Error("Вкажіть текст тестового повідомлення."), { statusCode: 400 });
      const id = randomUUID();
      await pool.query("INSERT INTO shieldline_outbox (id, actor_id, type, payload) VALUES ($1,$2,'admin.test',$3::jsonb)", [id, user.id, JSON.stringify({ text: message, test: true })]);
      await audit(pool, actor, "notification.test", user.id, reason, null, { outboxId: id }, requestId);
      return { id, actorId: user.id, queued: true };
    },
    async listBroadcasts() {
      return (await pool.query("SELECT * FROM shieldline_admin_broadcasts ORDER BY created_at DESC LIMIT 50")).rows;
    },
    async retryOutbox(actor, reason, requestId) {
      const result = await pool.query("UPDATE shieldline_outbox SET available_at = now() WHERE delivered_at IS NULL AND attempts > 0 RETURNING id");
      await audit(pool, actor, "outbox.retry", null, reason || "Повтор доставлення", null, { queued: result.rowCount }, requestId);
      return { queued: result.rowCount };
    },
    async createTelegramAction(adminTelegramId, action, payload, step = 1) {
      const token = randomBytes(18).toString("base64url");
      await pool.query("INSERT INTO shieldline_admin_actions (token_hash, admin_telegram_id, action, payload, step, expires_at) VALUES ($1,$2,$3,$4::jsonb,$5,now() + interval '5 minutes')", [hashSessionToken(token), String(adminTelegramId), action, JSON.stringify(payload || {}), step]);
      return token;
    },
    async consumeTelegramAction(token, adminTelegramId) {
      const result = await pool.query("UPDATE shieldline_admin_actions SET consumed_at = now() WHERE token_hash = $1 AND admin_telegram_id = $2 AND consumed_at IS NULL AND expires_at > now() RETURNING action, payload, step", [hashSessionToken(token), String(adminTelegramId)]);
      return result.rows[0] || null;
    },
    async beginBotUpdate(updateId) {
      const result = await pool.query("INSERT INTO shieldline_bot_updates (update_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING update_id", [updateId]);
      return Boolean(result.rowCount);
    },
    async finishBotUpdate(updateId, status = "processed") {
      await pool.query("UPDATE shieldline_bot_updates SET status = $2, processed_at = now() WHERE update_id = $1", [updateId, status]);
    },
  };
}

export async function createConfiguredAdminStore(env = process.env) {
  const pool = new Pool({
    host: env.SHIELDLINE_DB_HOST || "db",
    port: Number(env.SHIELDLINE_DB_PORT || 5432),
    user: env.SHIELDLINE_DB_USER,
    password: env.SHIELDLINE_DB_PASSWORD,
    database: env.SHIELDLINE_DB_NAME,
    max: Number(env.SHIELDLINE_ADMIN_DB_POOL_MAX || 5),
    connectionTimeoutMillis: Number(env.SHIELDLINE_DB_CONNECT_TIMEOUT_MS || 5_000),
  });
  return createAdminStore({ pool });
}
