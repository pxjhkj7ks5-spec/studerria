import bcrypt from "bcryptjs";
import type { Db } from "./db.js";
import type { AppConfig } from "./config.js";

const ddl = [
  `
    CREATE TABLE IF NOT EXISTS wa_users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL DEFAULT '',
      display_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('dev', 'deanery', 'teacher')),
      phone_e164 TEXT,
      whatsapp_wa_id TEXT UNIQUE,
      is_active BOOLEAN NOT NULL DEFAULT true,
      last_login_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  "CREATE INDEX IF NOT EXISTS wa_users_role_idx ON wa_users(role)",
  "CREATE INDEX IF NOT EXISTS wa_users_phone_idx ON wa_users(phone_e164)",
  `
    CREATE TABLE IF NOT EXISTS wa_teacher_invites (
      id SERIAL PRIMARY KEY,
      teacher_user_id INTEGER NOT NULL REFERENCES wa_users(id) ON DELETE CASCADE,
      code TEXT NOT NULL UNIQUE,
      created_by_user_id INTEGER REFERENCES wa_users(id) ON DELETE SET NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  "CREATE INDEX IF NOT EXISTS wa_teacher_invites_teacher_idx ON wa_teacher_invites(teacher_user_id)",
  `
    CREATE TABLE IF NOT EXISTS wa_tasks (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      assignee_user_id INTEGER NOT NULL REFERENCES wa_users(id) ON DELETE RESTRICT,
      created_by_user_id INTEGER REFERENCES wa_users(id) ON DELETE SET NULL,
      due_at TIMESTAMPTZ NOT NULL,
      due_has_time BOOLEAN NOT NULL DEFAULT false,
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'done', 'overdue', 'reopened', 'cancelled')),
      done_comment TEXT,
      done_at TIMESTAMPTZ,
      cancelled_at TIMESTAMPTZ,
      reopened_at TIMESTAMPTZ,
      last_reminder_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  "CREATE INDEX IF NOT EXISTS wa_tasks_assignee_idx ON wa_tasks(assignee_user_id, status, due_at)",
  "CREATE INDEX IF NOT EXISTS wa_tasks_status_idx ON wa_tasks(status, due_at)",
  `
    CREATE TABLE IF NOT EXISTS wa_task_events (
      id SERIAL PRIMARY KEY,
      task_id INTEGER NOT NULL REFERENCES wa_tasks(id) ON DELETE CASCADE,
      actor_user_id INTEGER REFERENCES wa_users(id) ON DELETE SET NULL,
      event_type TEXT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  "CREATE INDEX IF NOT EXISTS wa_task_events_task_idx ON wa_task_events(task_id, created_at DESC)",
  `
    CREATE TABLE IF NOT EXISTS wa_reminder_jobs (
      id SERIAL PRIMARY KEY,
      task_id INTEGER NOT NULL REFERENCES wa_tasks(id) ON DELETE CASCADE,
      kind TEXT NOT NULL CHECK (kind IN ('assigned', 'd1', 'due_day', 'overdue')),
      scheduled_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'skipped', 'failed')),
      idempotency_key TEXT NOT NULL UNIQUE,
      attempts INTEGER NOT NULL DEFAULT 0,
      sent_at TIMESTAMPTZ,
      last_error TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  "CREATE INDEX IF NOT EXISTS wa_reminder_jobs_due_idx ON wa_reminder_jobs(status, scheduled_at)",
  `
    CREATE TABLE IF NOT EXISTS wa_message_logs (
      id SERIAL PRIMARY KEY,
      direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
      whatsapp_message_id TEXT UNIQUE,
      contact_wa_id TEXT,
      user_id INTEGER REFERENCES wa_users(id) ON DELETE SET NULL,
      task_id INTEGER REFERENCES wa_tasks(id) ON DELETE SET NULL,
      kind TEXT NOT NULL DEFAULT 'message',
      status TEXT NOT NULL DEFAULT 'received',
      payload JSONB NOT NULL DEFAULT '{}'::jsonb,
      error TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `,
  "CREATE INDEX IF NOT EXISTS wa_message_logs_contact_idx ON wa_message_logs(contact_wa_id, created_at DESC)",
  "CREATE INDEX IF NOT EXISTS wa_message_logs_task_idx ON wa_message_logs(task_id, created_at DESC)",
];

export async function migrate(pool: Db) {
  for (const statement of ddl) {
    await pool.query(statement);
  }
}

export async function seedDevUser(pool: Db, config: AppConfig) {
  const passwordHash = await bcrypt.hash(config.devPassword, 12);
  await pool.query(
    `
      INSERT INTO wa_users (email, password_hash, display_name, role)
      VALUES ($1, $2, 'Dev', 'dev')
      ON CONFLICT (email) DO UPDATE
      SET password_hash = EXCLUDED.password_hash,
          role = 'dev',
          is_active = true,
          updated_at = NOW()
    `,
    [config.devEmail, passwordHash],
  );
}
