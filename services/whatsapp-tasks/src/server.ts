import path from "node:path";
import { fileURLToPath } from "node:url";
import express, { type Request, type Response } from "express";
import { loadConfig, withBasePath } from "./config.js";
import { createPool } from "./db.js";
import { migrate, seedDevUser } from "./migrations.js";
import { authenticate, canManageTasks, canManageUsers, clearSessionCookie, loadSessionUser, setSessionCookie, type SessionUser } from "./auth.js";
import { createOpenTeacherInvite, createTask, createUser, findTeacherTaskForInbound, linkInviteCode, parseDoneCommand, updateTaskStatus, completeTask } from "./domain.js";
import { renderDashboard, renderLogin, type DashboardData } from "./render.js";
import { logOutboundMessage, redactWhatsAppPayload, sendTextMessage, verifyWhatsAppSignature } from "./whatsapp.js";
import { startReminderWorker } from "./reminders.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const config = loadConfig();
const pool = createPool(config);
const app = express();
const router = express.Router();

function redirect(res: Response, target: string) {
  res.redirect(withBasePath(config, target));
}

async function currentUser(req: Request) {
  return loadSessionUser(req, pool, config);
}

function requireUser(handler: (req: Request, res: Response, user: SessionUser) => Promise<void>) {
  return async (req: Request, res: Response) => {
    const user = await currentUser(req);
    if (!user) return redirect(res, "/admin/login");
    return handler(req, res, user).catch((err) => {
      console.error("WA Tasks route failed", err);
      res.status(500).send("Internal error");
    });
  };
}

async function loadDashboardData(req: Request): Promise<DashboardData> {
  const status = String(req.query.status || "").trim();
  const where = status ? "WHERE t.status = $1" : "";
  const params = status ? [status] : [];
  const [stats, failed, teachers, tasks, users, invites] = await Promise.all([
    pool.query("SELECT status, COUNT(*)::int AS count FROM wa_tasks GROUP BY status"),
    pool.query("SELECT COUNT(*)::int AS count FROM wa_message_logs WHERE direction = 'outbound' AND status = 'failed'"),
    pool.query("SELECT id, display_name, email, phone_e164, whatsapp_wa_id FROM wa_users WHERE role = 'teacher' AND is_active = true ORDER BY display_name ASC"),
    pool.query(
      `
        SELECT t.*, u.display_name AS assignee_name
        FROM wa_tasks t
        JOIN wa_users u ON u.id = t.assignee_user_id
        ${where}
        ORDER BY
          CASE t.status WHEN 'overdue' THEN 0 WHEN 'open' THEN 1 WHEN 'reopened' THEN 2 WHEN 'done' THEN 3 ELSE 4 END,
          t.due_at ASC
        LIMIT 80
      `,
      params,
    ),
    pool.query("SELECT id, display_name, email, role, phone_e164, whatsapp_wa_id FROM wa_users ORDER BY role, display_name"),
    pool.query(
      `
        SELECT code, label, max_uses, use_count, expires_at
        FROM wa_teacher_invites
        WHERE invite_type = 'open_teacher'
          AND expires_at > NOW()
          AND use_count < max_uses
        ORDER BY created_at DESC
        LIMIT 10
      `,
    ),
  ]);

  const statMap: Record<string, number> = { open: 0, done: 0, overdue: 0, failed: Number(failed.rows[0]?.count || 0) };
  for (const row of stats.rows) statMap[row.status] = Number(row.count);
  const selectedTaskId = tasks.rows[0]?.id;
  const [events, logs] = selectedTaskId
    ? await Promise.all([
        pool.query("SELECT * FROM wa_task_events WHERE task_id = $1 ORDER BY created_at DESC LIMIT 20", [selectedTaskId]),
        pool.query("SELECT * FROM wa_message_logs WHERE task_id = $1 ORDER BY created_at DESC LIMIT 12", [selectedTaskId]),
      ])
    : [{ rows: [] }, { rows: [] }];

  return {
    stats: statMap,
    teachers: teachers.rows,
    tasks: tasks.rows,
    users: users.rows,
    invites: invites.rows,
    events: events.rows,
    logs: logs.rows,
    flash: String(req.query.flash || ""),
  };
}

router.get("/_health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "whatsapp-tasks" });
  } catch {
    res.status(503).json({ ok: false, service: "whatsapp-tasks" });
  }
});

router.get("/api/whatsapp/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];
  if (mode === "subscribe" && token === config.whatsapp.verifyToken && typeof challenge === "string") {
    res.status(200).send(challenge);
    return;
  }
  res.sendStatus(403);
});

router.post("/api/whatsapp/webhook", express.raw({ type: "application/json", limit: "2mb" }), async (req, res) => {
  const rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.from("");
  if (!verifyWhatsAppSignature(rawBody, req.headers["x-hub-signature-256"], config.whatsapp.appSecret)) {
    res.sendStatus(401);
    return;
  }

  let payload: any;
  try {
    payload = JSON.parse(rawBody.toString("utf8"));
  } catch {
    res.sendStatus(400);
    return;
  }

  for (const entry of payload.entry || []) {
    for (const change of entry.changes || []) {
      const value = change.value || {};
      const contactsByWaId = new Map<string, string>();
      for (const contact of value.contacts || []) {
        if (contact.wa_id) contactsByWaId.set(String(contact.wa_id), String(contact.profile?.name || ""));
      }
      for (const status of value.statuses || []) {
        await pool.query(
          `
            UPDATE wa_message_logs
            SET status = $2,
                payload = payload || $3::jsonb,
                updated_at = NOW()
            WHERE whatsapp_message_id = $1
          `,
          [status.id, status.status || "status", JSON.stringify({ status: redactWhatsAppPayload(status) })],
        );
      }

      for (const message of value.messages || []) {
        const messageId = String(message.id || "");
        const from = String(message.from || "");
        const text = String(message.text?.body || "").trim();
        if (!messageId || !from) continue;
        const inserted = await pool.query(
          `
            INSERT INTO wa_message_logs (direction, whatsapp_message_id, contact_wa_id, kind, status, payload)
            VALUES ('inbound', $1, $2, $3, 'received', $4::jsonb)
            ON CONFLICT (whatsapp_message_id) DO NOTHING
            RETURNING id
          `,
          [messageId, from, message.type || "message", JSON.stringify(redactWhatsAppPayload(message))],
        );
        if (!inserted.rows[0] || !text) continue;

        const inviteCode = /[A-Z2-9]{4}-[A-Z2-9]{4}/i.exec(text)?.[0] || text;
        const linked = await linkInviteCode(pool, inviteCode, from, contactsByWaId.get(from) || "");
        if (linked) {
          const prefix = linked.created ? "Реєстрацію завершено" : linked.alreadyLinked ? "WhatsApp уже підключено" : "WhatsApp підключено";
          await sendTextMessage(config, from, `${prefix}, ${linked.displayName}.`);
          continue;
        }

        const userResult = await pool.query("SELECT id, display_name FROM wa_users WHERE whatsapp_wa_id = $1 AND role = 'teacher' AND is_active = true", [from]);
        const teacher = userResult.rows[0];
        const done = parseDoneCommand(text);
        if (teacher && done) {
          const taskId = await findTeacherTaskForInbound(pool, Number(teacher.id), text);
          if (!taskId) {
            await sendTextMessage(config, from, "Не бачу відкритих задач для закриття.");
            continue;
          }
          const completed = await completeTask(pool, { taskId, actorUserId: Number(teacher.id), comment: done.comment });
          await sendTextMessage(config, from, completed ? `Готово. Задачу #${completed.id} закрито.` : "Не вдалося закрити задачу.");
        }
      }
    }
  }
  res.sendStatus(200);
});

router.use(express.urlencoded({ extended: false }));
router.use("/static", express.static(path.join(__dirname, "public"), { maxAge: "1h" }));

router.get("/", (_req, res) => redirect(res, "/admin"));

router.get("/admin/login", (_req, res) => {
  res.send(renderLogin(config));
});

router.post("/admin/login", async (req, res) => {
  const user = await authenticate(pool, String(req.body.email || ""), String(req.body.password || ""));
  if (!user) {
    res.status(401).send(renderLogin(config, "Невірний email або пароль."));
    return;
  }
  setSessionCookie(res, user.id, config);
  redirect(res, "/admin");
});

router.post("/admin/logout", (_req, res) => {
  clearSessionCookie(res, config);
  redirect(res, "/admin/login");
});

router.get("/admin", requireUser(async (req, res, user) => {
  res.send(renderDashboard(config, user, await loadDashboardData(req)));
}));

router.post("/admin/users", requireUser(async (req, res, user) => {
  const role = String(req.body.role || "teacher") as "teacher" | "deanery";
  if (!canManageUsers(user, role)) {
    res.status(403).send("Forbidden");
    return;
  }
  const created = await createUser(pool, {
    actor: user,
    email: String(req.body.email || ""),
    displayName: String(req.body.displayName || ""),
    role,
    phone: String(req.body.phone || ""),
    password: String(req.body.password || ""),
  });
  const flash = created.inviteCode
    ? `Викладача створено. Invite code: ${created.inviteCode}`
    : `Користувача створено. Temporary password: ${created.password}`;
  redirect(res, `/admin?flash=${encodeURIComponent(flash)}#teachers`);
}));

router.post("/admin/invites/open-teacher", requireUser(async (req, res, user) => {
  if (!canManageTasks(user)) {
    res.status(403).send("Forbidden");
    return;
  }
  const invite = await createOpenTeacherInvite(pool, {
    actor: user,
    label: String(req.body.label || ""),
    maxUses: Number(req.body.maxUses || 200),
  });
  redirect(res, `/admin?flash=${encodeURIComponent(`Open invite створено: ${invite.code}`)}#teachers`);
}));

router.post("/admin/tasks", requireUser(async (req, res, user) => {
  if (!canManageTasks(user)) {
    res.status(403).send("Forbidden");
    return;
  }
  const taskId = await createTask(pool, {
    actor: user,
    title: String(req.body.title || ""),
    description: String(req.body.description || ""),
    assigneeUserId: Number(req.body.assigneeUserId),
    dueDate: String(req.body.dueDate || ""),
    dueTime: String(req.body.dueTime || "") || undefined,
  });
  redirect(res, `/admin?flash=${encodeURIComponent(`Задачу #${taskId} створено.`)}`);
}));

router.post("/admin/tasks/:id/cancel", requireUser(async (req, res, user) => {
  if (!canManageTasks(user)) {
    res.status(403).send("Forbidden");
    return;
  }
  await updateTaskStatus(pool, { actor: user, taskId: Number(req.params.id), status: "cancelled" });
  redirect(res, "/admin");
}));

router.post("/admin/tasks/:id/reopen", requireUser(async (req, res, user) => {
  if (!canManageTasks(user)) {
    res.status(403).send("Forbidden");
    return;
  }
  await updateTaskStatus(pool, { actor: user, taskId: Number(req.params.id), status: "reopened" });
  redirect(res, "/admin");
}));

app.disable("x-powered-by");
app.use(config.basePath || "/", router);
if (config.basePath) {
  app.get("/", (_req, res) => redirect(res, "/admin"));
}

async function main() {
  await migrate(pool);
  await seedDevUser(pool, config);
  startReminderWorker(pool, config);
  app.listen(config.port, "0.0.0.0", () => {
    console.log(`WA Tasks listening on ${config.port}${config.basePath}`);
  });
}

if (process.env.NODE_ENV !== "test") {
  main().catch((err) => {
    console.error("WA Tasks failed to start", err);
    process.exit(1);
  });
}

export { app, pool };
