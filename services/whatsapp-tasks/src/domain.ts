import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import type { PoolClient } from "pg";
import type { Db } from "./db.js";
import { withTransaction } from "./db.js";
import type { Role, SessionUser } from "./auth.js";
import { buildReminderSchedule, kyivWallTimeToUtc } from "./time.js";

export type TaskStatus = "open" | "done" | "overdue" | "reopened" | "cancelled";

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

export function normalizePhone(value: string) {
  const trimmed = value.trim().replace(/[^\d+]/g, "");
  if (!/^\+[1-9]\d{7,14}$/.test(trimmed)) {
    throw new Error("invalid_phone");
  }
  return trimmed;
}

export function generateInviteCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "";
  const bytes = crypto.randomBytes(8);
  for (const byte of bytes) code += alphabet[byte % alphabet.length];
  return `${code.slice(0, 4)}-${code.slice(4, 8)}`;
}

async function addTaskEvent(client: PoolClient, taskId: number, actorUserId: number | null, eventType: string, note = "", metadata: Record<string, unknown> = {}) {
  await client.query(
    "INSERT INTO wa_task_events (task_id, actor_user_id, event_type, note, metadata) VALUES ($1, $2, $3, $4, $5::jsonb)",
    [taskId, actorUserId, eventType, note, JSON.stringify(metadata)],
  );
}

export async function createUser(pool: Db, input: {
  actor: SessionUser;
  email: string;
  displayName: string;
  role: Role;
  phone?: string;
  password?: string;
}) {
  const email = normalizeEmail(input.email);
  const phone = input.phone ? normalizePhone(input.phone) : null;
  const password = input.password?.trim() || crypto.randomBytes(10).toString("base64url");
  const passwordHash = input.role === "teacher" ? "" : await bcrypt.hash(password, 12);

  return withTransaction(pool, async (client) => {
    const created = await client.query(
      `
        INSERT INTO wa_users (email, password_hash, display_name, role, phone_e164)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, email, display_name, role, phone_e164
      `,
      [email, passwordHash, input.displayName.trim(), input.role, phone],
    );
    const user = created.rows[0];
    let inviteCode = "";
    if (input.role === "teacher") {
      inviteCode = generateInviteCode();
      await client.query(
        `
          INSERT INTO wa_teacher_invites (teacher_user_id, code, created_by_user_id, expires_at)
          VALUES ($1, $2, $3, NOW() + INTERVAL '30 days')
        `,
        [user.id, inviteCode, input.actor.id],
      );
    }
    return {
      id: Number(user.id),
      email: user.email as string,
      displayName: user.display_name as string,
      role: user.role as Role,
      phone: user.phone_e164 as string | null,
      password: input.role === "teacher" ? "" : password,
      inviteCode,
    };
  });
}

export async function linkInviteCode(pool: Db, code: string, waId: string) {
  const normalizedCode = code.trim().toUpperCase();
  return withTransaction(pool, async (client) => {
    const result = await client.query(
      `
        SELECT i.id AS invite_id, i.teacher_user_id, u.display_name
        FROM wa_teacher_invites i
        JOIN wa_users u ON u.id = i.teacher_user_id
        WHERE i.code = $1
          AND i.used_at IS NULL
          AND i.expires_at > NOW()
          AND u.role = 'teacher'
          AND u.is_active = true
        FOR UPDATE
      `,
      [normalizedCode],
    );
    const row = result.rows[0];
    if (!row) return null;
    await client.query("UPDATE wa_users SET whatsapp_wa_id = $1, updated_at = NOW() WHERE id = $2", [waId, row.teacher_user_id]);
    await client.query("UPDATE wa_teacher_invites SET used_at = NOW() WHERE id = $1", [row.invite_id]);
    return {
      teacherUserId: Number(row.teacher_user_id),
      displayName: row.display_name as string,
    };
  });
}

export async function createTask(pool: Db, input: {
  actor: SessionUser;
  title: string;
  description: string;
  assigneeUserId: number;
  dueDate: string;
  dueTime?: string;
}) {
  const title = input.title.trim();
  if (title.length < 3) throw new Error("invalid_title");
  const dueHasTime = Boolean(input.dueTime);
  const dueAt = input.dueTime ? kyivWallTimeToUtc(input.dueDate, Number(input.dueTime.slice(0, 2)), Number(input.dueTime.slice(3, 5))) : kyivWallTimeToUtc(input.dueDate, 23, 59);
  const schedule = buildReminderSchedule({ dueDateKey: input.dueDate, dueTime: input.dueTime || null });

  return withTransaction(pool, async (client) => {
    const assignee = await client.query("SELECT id, role FROM wa_users WHERE id = $1 AND role = 'teacher' AND is_active = true", [input.assigneeUserId]);
    if (!assignee.rows[0]) throw new Error("assignee_not_found");

    const created = await client.query(
      `
        INSERT INTO wa_tasks (title, description, assignee_user_id, created_by_user_id, due_at, due_has_time)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
      `,
      [title, input.description.trim(), input.assigneeUserId, input.actor.id, dueAt, dueHasTime],
    );
    const taskId = Number(created.rows[0].id);
    await addTaskEvent(client, taskId, input.actor.id, "created", "", { dueDate: input.dueDate, dueTime: input.dueTime || "" });

    const jobs = [
      ["assigned", schedule.assignedAt],
      ["d1", schedule.dayBeforeAt],
      ["due_day", schedule.dueDayAt],
      ["overdue", schedule.overdueAt],
    ] as const;
    for (const [kind, scheduledAt] of jobs) {
      if (!scheduledAt) continue;
      await client.query(
        `
          INSERT INTO wa_reminder_jobs (task_id, kind, scheduled_at, idempotency_key)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (idempotency_key) DO NOTHING
        `,
        [taskId, kind, scheduledAt, `task:${taskId}:${kind}`],
      );
    }
    return taskId;
  });
}

export async function completeTask(pool: Db, input: {
  taskId: number;
  actorUserId: number;
  comment?: string;
}) {
  return withTransaction(pool, async (client) => {
    const result = await client.query(
      `
        UPDATE wa_tasks
        SET status = 'done',
            done_comment = NULLIF($3, ''),
            done_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
          AND assignee_user_id = $2
          AND status IN ('open', 'reopened', 'overdue')
        RETURNING id, title
      `,
      [input.taskId, input.actorUserId, input.comment?.trim() || ""],
    );
    const row = result.rows[0];
    if (!row) return null;
    await addTaskEvent(client, input.taskId, input.actorUserId, "done", input.comment?.trim() || "");
    return { id: Number(row.id), title: row.title as string };
  });
}

export async function updateTaskStatus(pool: Db, input: {
  actor: SessionUser;
  taskId: number;
  status: Extract<TaskStatus, "reopened" | "cancelled">;
}) {
  const field = input.status === "reopened" ? "reopened_at" : "cancelled_at";
  await withTransaction(pool, async (client) => {
    await client.query(
      `UPDATE wa_tasks SET status = $1, ${field} = NOW(), updated_at = NOW() WHERE id = $2`,
      [input.status, input.taskId],
    );
    await addTaskEvent(client, input.taskId, input.actor.id, input.status);
  });
}

export async function findTeacherTaskForInbound(pool: Db, teacherUserId: number, text: string) {
  const explicitId = /(?:#|task\s*)?(\d{1,8})/i.exec(text)?.[1];
  if (explicitId) {
    const result = await pool.query(
      "SELECT id FROM wa_tasks WHERE id = $1 AND assignee_user_id = $2 AND status IN ('open', 'reopened', 'overdue')",
      [Number(explicitId), teacherUserId],
    );
    if (result.rows[0]) return Number(result.rows[0].id);
  }
  const result = await pool.query(
    `
      SELECT id
      FROM wa_tasks
      WHERE assignee_user_id = $1
        AND status IN ('open', 'reopened', 'overdue')
      ORDER BY due_at ASC, id ASC
      LIMIT 1
    `,
    [teacherUserId],
  );
  return result.rows[0] ? Number(result.rows[0].id) : null;
}

export function parseDoneCommand(text: string) {
  const normalized = text.trim();
  const match = /^(?:done|готово|виконано)(?:\s+(.+))?$/i.exec(normalized) || /^#?\d+\s+(?:done|готово|виконано)(?:\s+(.+))?$/i.exec(normalized);
  if (!match) return null;
  return {
    comment: (match[1] || "").trim(),
  };
}
