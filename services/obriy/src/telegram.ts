import { z } from "zod";
import { type Store, type Delivery } from "./store.js";
import { type Config } from "./config.js";
import {
  type NormalizedTrack,
  type RiskAssessment,
  type AlertLevel,
} from "./engine/index.js";

export const DISCLAIMER =
  "Дані моніторингу не замінюють офіційний сигнал повітряної тривоги.";
const names: Record<string, string> = {
  uav: "БпЛА",
  fpv: "БпЛА",
  recon: "Розвідувальний БпЛА",
  missile: "Ракета",
  ballistic: "Балістична загроза",
  kab: "Авіаційна загроза",
  mig31k: "Авіаційна активність",
};
export function riskText(
  track: NormalizedTrack,
  assessment: RiskAssessment,
  level: AlertLevel,
): string {
  if (level === "RESOLVED")
    return `Джерело більше не показує попереднє спостереження. Це не означає відбій тривоги.\n\n${DISCLAIMER}\nДжерело: NEPTUN — https://neptun.in.ua`;
  const kind = names[track.threat.type] ?? "Повітряна загроза";
  const approaching = assessment.explanationCodes.includes("APPROACHING");
  return [
    level === "HIGH" ? "🚨 Потенційна загроза" : "⚠️ Увага до обраної зони",
    `${kind}: ${approaching ? "може наближатися до обраної зони." : "спостереження поблизу обраної зони."}`,
    assessment.geometry.distanceBand
      ? `Приблизна відстань: ${assessment.geometry.distanceBand}.`
      : "",
    assessment.geometry.corridorIntersects
      ? "Оцінений коридор може перетнути захисну зону."
      : "",
    `Рівень: ${level}.`,
    "",
    DISCLAIMER,
    "Джерело: NEPTUN — https://neptun.in.ua",
  ]
    .filter(Boolean)
    .join("\n");
}
export class TelegramError extends Error {
  constructor(
    readonly code: string,
    readonly retryAfter = 0,
    readonly permanent = false,
  ) {
    super(code);
  }
}
export class TelegramClient {
  constructor(
    private readonly token: string,
    private readonly fetcher: typeof fetch = fetch,
  ) {}
  async call(
    method:
      | "sendMessage"
      | "getUpdates"
      | "answerCallbackQuery"
      | "getMe"
      | "getWebhookInfo",
    body: unknown,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetcher(
        `https://api.telegram.org/bot${this.token}/${method}`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(method === "getUpdates" ? 35000 : 12000),
          redirect: "error",
        },
      );
    } catch {
      throw new TelegramError("network");
    }
    const raw = await response.text();
    if (raw.length > 1_048_576) throw new TelegramError("oversized_response");
    let data: {
      ok?: boolean;
      result?: unknown;
      error_code?: number;
      parameters?: { retry_after?: number };
    };
    try {
      data = JSON.parse(raw);
    } catch {
      throw new TelegramError("invalid_response");
    }
    const code = data.error_code ?? response.status;
    if (!response.ok || !data.ok) {
      const retry = Number(data.parameters?.retry_after);
      throw new TelegramError(
        `http_${code}`,
        Number.isFinite(retry) ? Math.min(86400, Math.max(1, retry)) : 0,
        [400, 401, 403, 404, 409].includes(code),
      );
    }
    return data.result;
  }
  async send(chatId: string, text: string) {
    await this.call("sendMessage", {
      chat_id: chatId,
      text,
      link_preview_options: { is_disabled: true },
      protect_content: true,
    });
  }
}
const updateSchema = z.object({
  update_id: z.number().int().nonnegative(),
  message: z
    .object({
      chat: z.object({ id: z.number().int(), type: z.string() }),
      from: z
        .object({ id: z.number().int(), is_bot: z.boolean().optional() })
        .optional(),
      text: z.string().max(4096).optional(),
    })
    .optional(),
});
export class TelegramBot {
  private stopped = true;
  private loop?: Promise<void>;
  private retryTimer?: ReturnType<typeof setTimeout>;
  private wake?: () => void;
  lastError: string | null = null;
  constructor(
    private readonly store: Store,
    private readonly config: Config,
    readonly client = new TelegramClient(config.OBRIY_TELEGRAM_BOT_TOKEN),
  ) {}
  async handle(raw: unknown) {
    const parsed = updateSchema.safeParse(raw);
    if (!parsed.success) return;
    const update = parsed.data,
      m = update.message;
    if (
      !m ||
      m.chat.type !== "private" ||
      !m.from ||
      m.from.is_bot ||
      m.from.id !== m.chat.id ||
      !m.text
    )
      return;
    const chatId = String(m.chat.id),
      [command, arg] = m.text.trim().split(/\s+/, 2);
    if (!command?.startsWith("/")) return;
    let deletion = false;
    await this.store.transaction(async (c) => {
      const inserted = await c.query(
        "INSERT INTO obriy.telegram_updates(update_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING update_id",
        [update.update_id],
      );
      if (!inserted.rowCount) return;
      let uid = await this.store.chatUser(chatId, c);
      if (command === "/start" && arg) {
        uid = await this.store.linkChat(c, arg, chatId);
        if (!uid) return;
      }
      if (!uid) return;
      // One command per chat per second; the opaque keyed hash never enters logs.
      const budget = await c.query(
        "SELECT count(*)::int AS n FROM obriy.notification_outbox WHERE user_id=$1 AND category='command' AND created_at>now()-interval '1 minute'",
        [uid],
      );
      if (budget.rows[0].n >= 20) return;
      let text = "";
      switch (command.split("@")[0]) {
        case "/start":
          text = `Обрій підключено. Сповіщення стосуються зон, які ви додали у приватному кабінеті.\n${this.config.OBRIY_PUBLIC_URL}\n\n/status · /zones · /pause · /resume · /privacy · /delete_me\n\n${DISCLAIMER}`;
          break;
        case "/status": {
          const user = await c.query(
            "SELECT paused_until FROM obriy.users WHERE id=$1",
            [uid],
          );
          const paused = user.rows[0]?.paused_until > new Date();
          const health = await c.query(
            "SELECT data,updated_at FROM obriy.runtime_state WHERE key='source-health'",
          );
          const fresh =
            health.rows[0] &&
            Date.now() - health.rows[0].updated_at.getTime() < 90000 &&
            health.rows[0].data.neptun?.state === "live";
          text = `Обрій: ${paused ? "сповіщення на паузі." : "сповіщення увімкнено."}\nДжерело спостережень: ${fresh ? "підключене." : "немає підтверджених свіжих даних."}\n${this.config.OBRIY_PUBLIC_URL}\n\n${DISCLAIMER}`;
          break;
        }
        case "/zones": {
          const result = await c.query(
            "SELECT count(*)::int AS n FROM obriy.zones WHERE user_id=$1",
            [uid],
          );
          text = `Збережених зон: ${result.rows[0].n}. Координати доступні лише у вашому приватному кабінеті.\n${this.config.OBRIY_PUBLIC_URL}`;
          break;
        }
        case "/pause":
          await this.store.pause(uid, 60, c);
          text =
            "Сповіщення призупинено на 1 годину. /resume — відновити.\nОфіційні тривоги залишаються чинними.";
          break;
        case "/resume":
          await this.store.pause(uid, 0, c);
          text = "Сповіщення відновлено для нових свіжих спостережень.";
          break;
        case "/privacy":
          text =
            "Координати зон та ідентифікатор чату зберігаються зашифрованими на нашому сервері. NEPTUN і alerts.in.ua не отримують ваші зони. Telegram бачить цей чат та текст повідомлень; це не наскрізно зашифрований секретний чат. Не надсилайте сюди координати чи адресу. /delete_me видаляє ваші дані з робочої бази; резервні копії очищаються за політикою зберігання.";
          break;
        case "/delete_me":
          await c.query("DELETE FROM obriy.users WHERE id=$1", [uid]);
          deletion = true;
          break;
        default:
          text = "Команди: /status /zones /pause /resume /privacy /delete_me";
      }
      if (text)
        await this.store.enqueue(
          c,
          uid,
          text,
          `telegram:${update.update_id}`,
          undefined,
          300,
        );
    });
    if (deletion)
      await this.client
        .send(
          chatId,
          "Ваші зони, налаштування, сесії та зв’язок із Telegram видалено з робочої бази Обрію.",
        )
        .catch(() => {});
  }
  start() {
    if (
      !this.stopped ||
      this.config.OBRIY_TELEGRAM_MODE !== "polling" ||
      !this.config.OBRIY_TELEGRAM_BOT_TOKEN
    )
      return;
    this.stopped = false;
    this.loop = this.poll();
  }
  private async delay(ms: number) {
    if (this.stopped) return;
    await new Promise<void>((resolve) => {
      this.wake = resolve;
      this.retryTimer = setTimeout(resolve, ms);
    });
    this.wake = undefined;
  }
  private async poll() {
    let offset = (await this.store.getRuntime<number>("telegram-offset")) ?? 0;
    while (!this.stopped) {
      try {
        const data = await this.client.call("getUpdates", {
          offset,
          timeout: 25,
          limit: 50,
          allowed_updates: ["message"],
        });
        if (!Array.isArray(data)) throw new TelegramError("invalid_updates");
        for (const raw of data) {
          if (this.stopped) break;
          await this.handle(raw);
          const id = (raw as { update_id?: number }).update_id;
          if (Number.isSafeInteger(id)) {
            offset = Math.max(offset, id! + 1);
            await this.store.setRuntime("telegram-offset", offset);
          }
        }
        this.lastError = null;
      } catch (error) {
        const e =
          error instanceof TelegramError
            ? error
            : new TelegramError("processing");
        this.lastError = e.code;
        await this.delay((e.retryAfter || (e.permanent ? 300 : 5)) * 1000);
      }
    }
  }
  async stop() {
    this.stopped = true;
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.wake?.();
    await this.loop;
  }
}
export class Dispatcher {
  private stopped = true;
  private timer?: ReturnType<typeof setTimeout>;
  private active?: Promise<void>;
  lastError: string | null = null;
  constructor(
    private readonly store: Store,
    private readonly client: TelegramClient,
    private readonly sourceFresh: () => boolean,
  ) {}
  start() {
    if (!this.stopped) return;
    this.stopped = false;
    this.schedule();
  }
  private schedule() {
    if (this.stopped) return;
    this.timer = setTimeout(() => {
      this.active = this.tick()
        .catch(() => {
          this.lastError = "storage";
        })
        .finally(() => this.schedule());
    }, 100);
  }
  async tick() {
    const d = await this.store.claim();
    if (!d) return;
    if (
      !(await this.store.deliverable(d)) ||
      (d.category === "risk" && !this.sourceFresh())
    ) {
      await this.store.finish(d, "cancelled");
      return;
    }
    try {
      await this.client.send(d.chatId, d.text);
      await this.store.finish(d, "sent");
      this.lastError = null;
    } catch (error) {
      const e =
        error instanceof TelegramError ? error : new TelegramError("delivery");
      this.lastError = e.code;
      await this.retry(d, e);
    }
  }
  private async retry(d: Delivery, e: TelegramError) {
    await this.store.finish(
      d,
      e.permanent || d.attempts >= 7 ? "dead" : "retry",
      e.retryAfter || Math.min(300, 2 ** d.attempts),
      e.code,
    );
  }
  async stop() {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    await this.active;
  }
}
