import type { Db } from "./db.js";
import type { AppConfig } from "./config.js";
import { logOutboundMessage, sendTemplateMessage, type WhatsAppTemplateName } from "./whatsapp.js";
import { formatKyivDateTime } from "./time.js";

function templateForKind(kind: string): WhatsAppTemplateName {
  if (kind === "assigned") return "wa_task_assigned_uk";
  if (kind === "overdue") return "wa_task_overdue_uk";
  return "wa_task_reminder_uk";
}

function reminderLabel(kind: string) {
  if (kind === "assigned") return "Нове завдання";
  if (kind === "d1") return "Нагадування за день";
  if (kind === "due_day") return "Нагадування сьогодні";
  return "Прострочене завдання";
}

export async function processReminderJobs(pool: Db, config: AppConfig, limit = 20) {
  const result = await pool.query(
    `
      SELECT
        j.id,
        j.kind,
        t.id AS task_id,
        t.title,
        t.status AS task_status,
        t.due_at,
        u.id AS user_id,
        u.display_name,
        u.whatsapp_wa_id
      FROM wa_reminder_jobs j
      JOIN wa_tasks t ON t.id = j.task_id
      JOIN wa_users u ON u.id = t.assignee_user_id
      WHERE j.status = 'pending'
        AND j.scheduled_at <= NOW()
      ORDER BY j.scheduled_at ASC, j.id ASC
      LIMIT $1
    `,
    [limit],
  );

  for (const row of result.rows) {
    const jobId = Number(row.id);
    await pool.query("UPDATE wa_reminder_jobs SET attempts = attempts + 1, updated_at = NOW() WHERE id = $1", [jobId]);
    if (!["open", "reopened", "overdue"].includes(row.task_status)) {
      await pool.query("UPDATE wa_reminder_jobs SET status = 'skipped', last_error = 'task_not_open', updated_at = NOW() WHERE id = $1", [jobId]);
      continue;
    }
    if (row.kind === "overdue" && row.task_status !== "overdue") {
      await pool.query(
        `
          UPDATE wa_tasks
          SET status = 'overdue', updated_at = NOW()
          WHERE id = $1 AND status IN ('open', 'reopened')
        `,
        [row.task_id],
      );
      await pool.query(
        "INSERT INTO wa_task_events (task_id, event_type, note) VALUES ($1, 'overdue', 'Автоматично позначено як прострочене.')",
        [row.task_id],
      );
    }
    if (!row.whatsapp_wa_id) {
      await pool.query("UPDATE wa_reminder_jobs SET status = 'skipped', last_error = 'teacher_not_linked', updated_at = NOW() WHERE id = $1", [jobId]);
      await logOutboundMessage(pool, {
        contactWaId: "",
        userId: Number(row.user_id),
        taskId: Number(row.task_id),
        kind: row.kind,
        status: "skipped",
        error: "teacher_not_linked",
      });
      continue;
    }

    const sent = await sendTemplateMessage(config, {
      to: row.whatsapp_wa_id,
      templateName: templateForKind(row.kind),
      bodyParams: [row.display_name, row.title, formatKyivDateTime(row.due_at), `#${row.task_id}`, reminderLabel(row.kind)],
    });
    await logOutboundMessage(pool, {
      whatsappMessageId: sent.messageId,
      contactWaId: row.whatsapp_wa_id,
      userId: Number(row.user_id),
      taskId: Number(row.task_id),
      kind: row.kind,
      status: sent.ok ? "sent" : sent.skipped ? "skipped" : "failed",
      payload: sent.payload,
      error: sent.error,
    });
    await pool.query(
      `
        UPDATE wa_reminder_jobs
        SET status = $2,
            sent_at = CASE WHEN $2 = 'sent' THEN NOW() ELSE sent_at END,
            last_error = NULLIF($3, ''),
            updated_at = NOW()
        WHERE id = $1
      `,
      [jobId, sent.ok ? "sent" : sent.skipped ? "skipped" : "failed", sent.error],
    );
    if (sent.ok) {
      await pool.query("UPDATE wa_tasks SET last_reminder_at = NOW(), updated_at = NOW() WHERE id = $1", [row.task_id]);
    }
  }

  return result.rowCount || 0;
}

export async function markOverdueTasks(pool: Db) {
  const result = await pool.query(
    `
      UPDATE wa_tasks
      SET status = 'overdue', updated_at = NOW()
      WHERE status IN ('open', 'reopened')
        AND due_at < NOW()
      RETURNING id
    `,
  );
  for (const row of result.rows) {
    await pool.query(
      "INSERT INTO wa_task_events (task_id, event_type, note) VALUES ($1, 'overdue', 'Автоматично позначено як прострочене.')",
      [row.id],
    );
  }
  return result.rowCount || 0;
}

export function startReminderWorker(pool: Db, config: AppConfig) {
  if (!config.workerEnabled) return null;
  const tick = async () => {
    try {
      await markOverdueTasks(pool);
      await processReminderJobs(pool, config);
    } catch (err) {
      console.error("WA Tasks worker failed", err);
    }
  };
  const timer = setInterval(tick, config.workerIntervalMs);
  timer.unref();
  void tick();
  return timer;
}
