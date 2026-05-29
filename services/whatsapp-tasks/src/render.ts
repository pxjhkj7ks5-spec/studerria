import type { AppConfig } from "./config.js";
import type { SessionUser } from "./auth.js";
import { formatKyivDateTime } from "./time.js";

export type DashboardData = {
  stats: Record<string, number>;
  teachers: Array<{ id: number; display_name: string; email: string; phone_e164: string | null; whatsapp_wa_id: string | null }>;
  tasks: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
  logs: Array<Record<string, unknown>>;
  users: Array<Record<string, unknown>>;
  invites: Array<Record<string, unknown>>;
  flash?: string;
};

function esc(value: unknown) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function href(config: AppConfig, path: string) {
  return `${config.basePath}${path}`;
}

function layout(config: AppConfig, user: SessionUser | null, body: string) {
  return `<!doctype html>
<html lang="uk">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WA Tasks</title>
  <link rel="stylesheet" href="${href(config, "/static/styles.css")}" />
</head>
<body>
  <div class="app-shell">
    <aside class="sidebar">
      <a class="brand" href="${href(config, "/admin")}"><span class="brand-mark">WA</span><span>Tasks</span></a>
      <nav>
        <a href="${href(config, "/admin")}">Dashboard</a>
        <a href="${href(config, "/admin#tasks")}">Tasks</a>
        <a href="${href(config, "/admin#teachers")}">Teachers</a>
        <a href="${href(config, "/admin#templates")}">Templates</a>
        <a href="${href(config, "/admin#logs")}">Logs</a>
      </nav>
      <div class="sidebar-foot">
        ${user ? `<span>${esc(user.displayName)}</span><small>${esc(user.role)}</small><form method="post" action="${href(config, "/admin/logout")}"><button>Вийти</button></form>` : ""}
      </div>
    </aside>
    <main class="main">
      ${body}
    </main>
  </div>
</body>
</html>`;
}

export function renderLogin(config: AppConfig, error = "") {
  return layout(config, null, `
    <section class="login-panel">
      <div>
        <h1>WA Tasks</h1>
        <p>Окремий сервіс для задач деканату, WhatsApp-нагадувань і контролю виконання.</p>
      </div>
      ${error ? `<div class="alert danger">${esc(error)}</div>` : ""}
      <form method="post" action="${href(config, "/admin/login")}" class="stack">
        <label>Email<input name="email" type="email" autocomplete="username" required /></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
        <button class="primary">Увійти</button>
      </form>
    </section>
  `);
}

function statusLabel(status: unknown) {
  const value = String(status || "");
  const labels: Record<string, string> = {
    open: "Відкрита",
    done: "Виконана",
    overdue: "Прострочена",
    reopened: "Повернена",
    cancelled: "Скасована",
  };
  return labels[value] || value;
}

export function renderDashboard(config: AppConfig, user: SessionUser, data: DashboardData) {
  const selectedTask = data.tasks[0];
  const taskRows = data.tasks.map((task) => `
    <tr>
      <td><strong>#${esc(task.id)}</strong><span>${esc(task.title)}</span></td>
      <td>${esc(task.assignee_name)}</td>
      <td>${esc(formatKyivDateTime(task.due_at as string))}</td>
      <td><span class="status ${esc(task.status)}">${esc(statusLabel(task.status))}</span></td>
      <td>${task.last_reminder_at ? esc(formatKyivDateTime(task.last_reminder_at as string)) : "—"}</td>
      <td class="row-actions">
        ${["open", "overdue", "reopened"].includes(String(task.status)) ? `<form method="post" action="${href(config, `/admin/tasks/${task.id}/cancel`)}"><button>Cancel</button></form>` : ""}
        ${String(task.status) === "overdue" ? `<form method="post" action="${href(config, `/admin/tasks/${task.id}/reopen`)}"><button>Reopen</button></form>` : ""}
      </td>
    </tr>
  `).join("");

  const teacherOptions = data.teachers.map((teacher) => `<option value="${teacher.id}">${esc(teacher.display_name)} · ${esc(teacher.phone_e164 || teacher.email)}</option>`).join("");
  const events = data.events.map((event) => `
    <li><time>${esc(formatKyivDateTime(event.created_at as string))}</time><strong>${esc(event.event_type)}</strong><span>${esc(event.note || "")}</span></li>
  `).join("");
  const logs = data.logs.map((log) => `
    <li>
      <time>${esc(formatKyivDateTime(log.created_at as string))}</time>
      <strong>${esc(log.kind)}</strong>
      <span class="${String(log.status) === "failed" ? "danger-text" : ""}">${esc(log.status)}</span>
      ${log.error ? `<small>${esc(log.error)}</small>` : ""}
    </li>
  `).join("");
  const users = data.users.map((row) => `
    <tr><td>${esc(row.display_name)}</td><td>${esc(row.email)}</td><td>${esc(row.role)}</td><td>${esc(row.phone_e164 || "—")}</td><td>${row.whatsapp_wa_id ? "Linked" : "Pending"}</td></tr>
  `).join("");
  const invites = data.invites.map((row) => `
    <tr>
      <td><code>${esc(row.code)}</code></td>
      <td>${esc(row.label || "—")}</td>
      <td>${esc(row.use_count)} / ${esc(row.max_uses)}</td>
      <td>${esc(formatKyivDateTime(row.expires_at as string))}</td>
    </tr>
  `).join("");

  return layout(config, user, `
    <header class="topbar">
      <div>
        <h1>Операційний контроль задач</h1>
        <p>Деканат призначає задачі викладачам, сервіс відстежує дедлайни й WhatsApp-доставку.</p>
      </div>
      <a class="primary action-link" href="#create-task">Нова задача</a>
    </header>
    ${data.flash ? `<div class="alert">${esc(data.flash)}</div>` : ""}
    <section class="metric-grid">
      <article><span>Open</span><strong>${data.stats.open || 0}</strong></article>
      <article><span>Done</span><strong>${data.stats.done || 0}</strong></article>
      <article><span>Overdue</span><strong>${data.stats.overdue || 0}</strong></article>
      <article><span>Failed sends</span><strong>${data.stats.failed || 0}</strong></article>
    </section>
    <section class="workspace">
      <div class="content-rail">
        <div class="toolbar" id="tasks">
          <h2>Tasks</h2>
          <form method="get" action="${href(config, "/admin")}">
            <select name="status">
              <option value="">All statuses</option>
              ${["open", "overdue", "done", "reopened", "cancelled"].map((status) => `<option value="${status}">${statusLabel(status)}</option>`).join("")}
            </select>
            <button>Фільтр</button>
          </form>
        </div>
        <table class="task-table">
          <thead><tr><th>Задача</th><th>Викладач</th><th>Дедлайн</th><th>Статус</th><th>Reminder</th><th></th></tr></thead>
          <tbody>${taskRows || `<tr><td colspan="6" class="empty">Задач ще немає.</td></tr>`}</tbody>
        </table>
        <section class="form-band" id="create-task">
          <h2>Створити задачу</h2>
          <form method="post" action="${href(config, "/admin/tasks")}" class="form-grid">
            <label>Назва<input name="title" required maxlength="180" /></label>
            <label>Викладач<select name="assigneeUserId" required>${teacherOptions}</select></label>
            <label>Дата<input name="dueDate" type="date" required /></label>
            <label>Час<input name="dueTime" type="time" /></label>
            <label class="wide">Опис<textarea name="description" rows="3"></textarea></label>
            <button class="primary">Створити</button>
          </form>
        </section>
        <section class="form-band" id="teachers">
          <h2>Користувачі та інвайти</h2>
          <form method="post" action="${href(config, "/admin/invites/open-teacher")}" class="invite-form">
            <label>Open invite label<input name="label" value="Самореєстрація викладачів" /></label>
            <label>Ліміт використань<input name="maxUses" type="number" min="1" max="500" value="200" /></label>
            <button class="primary">Створити open invite</button>
          </form>
          <form method="post" action="${href(config, "/admin/users")}" class="form-grid">
            <label>Імʼя<input name="displayName" required /></label>
            <label>Email<input name="email" type="email" required /></label>
            <label>Роль<select name="role"><option value="teacher">Викладач</option>${user.role === "dev" ? '<option value="deanery">Деканат</option>' : ""}</select></label>
            <label>Телефон E.164<input name="phone" placeholder="+380..." /></label>
            <label>Пароль<input name="password" type="password" placeholder="для деканату" /></label>
            <button class="primary">Створити</button>
          </form>
          <h3 class="subhead">Open invites</h3>
          <table class="compact-table"><thead><tr><th>Код</th><th>Label</th><th>Uses</th><th>До</th></tr></thead><tbody>${invites || `<tr><td colspan="4" class="empty">Open invite ще немає.</td></tr>`}</tbody></table>
          <table class="compact-table"><thead><tr><th>Імʼя</th><th>Email</th><th>Role</th><th>Phone</th><th>WhatsApp</th></tr></thead><tbody>${users}</tbody></table>
        </section>
      </div>
      <aside class="inspector">
        <section>
          <h2>Selected task</h2>
          ${selectedTask ? `<p class="task-title">#${esc(selectedTask.id)} ${esc(selectedTask.title)}</p><p>${esc(selectedTask.description || "Без опису")}</p>` : `<p class="muted">Оберіть або створіть задачу.</p>`}
        </section>
        <section>
          <h3>Timeline</h3>
          <ol class="timeline">${events || `<li><span>Подій ще немає.</span></li>`}</ol>
        </section>
        <section id="templates">
          <h3>Templates</h3>
          <ul class="template-list"><li>wa_task_assigned_uk</li><li>wa_task_reminder_uk</li><li>wa_task_overdue_uk</li></ul>
        </section>
        <section id="logs">
          <h3>Delivery log</h3>
          <ol class="delivery-log">${logs || `<li><span>Логів ще немає.</span></li>`}</ol>
        </section>
      </aside>
    </section>
  `);
}
