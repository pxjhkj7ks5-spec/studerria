import { AlertTriangle, CheckCircle2, FileText, Info, Radio, Rocket, ShieldCheck, Target } from "lucide-react";
import type { GameState, IntelTone } from "../types/game";

interface IntelLogProps {
  game: GameState;
}

const toneIcon: Record<IntelTone, typeof Info> = {
  info: Info,
  success: CheckCircle2,
  warning: Radio,
  danger: AlertTriangle,
};

const weatherLabel: Record<GameState["forecast"]["weather"], string> = {
  clear: "ясно",
  poor: "складні умови",
  storm: "шторм",
};

function eventVisual(entry: GameState["log"][number]) {
  const key = entry.title.toLowerCase();
  if (entry.eventType === "launch" || key.includes("пуск") || key.includes("launch")) return { kind: "launch", Icon: Rocket };
  if (entry.eventType === "detection" || key.includes("радар") || key.includes("track") || key.includes("ціль")) return { kind: "radar", Icon: Radio };
  if (key.includes("intercept") || key.includes("перехоп")) return { kind: "intercept", Icon: ShieldCheck };
  if (key.includes("impact") || key.includes("влуч")) return { kind: "hit", Icon: Target };
  if (key.includes("report") || key.includes("звіт")) return { kind: "report", Icon: FileText };
  return { kind: entry.tone, Icon: toneIcon[entry.tone] };
}

function localizedEntry(entry: GameState["log"][number]) {
  if (entry.eventType === "launch" || entry.eventType === "detection" || /[А-Яа-яІіЇїЄє]/.test(entry.title)) return entry;
  if (entry.title.endsWith(" Placed")) return { ...entry, title: "ППО розміщено", body: "Установку додано до системи протиповітряної оборони." };
  if (entry.title.endsWith(" Recalled")) return { ...entry, title: "ППО відкликано", body: "Установку знято з позиції, частину ресурсу повернено." };
  const copy: Record<string, [string, string]> = {
    "Track Warning": ["Попередження про ціль", "На тактичній мапі з’явилася нова непідтверджена ціль."],
    "Intercept Confirmed": ["Перехоплення підтверджено", "Підрозділ ППО нейтралізував повітряну ціль."],
    Engagement: ["Бойова робота", "Установка ППО розпочала перехоплення цілі."],
    Impact: ["Влучання", "Ціль дісталася захищеної області."],
    "Threat Director": ["Оперативна обстановка", "Розвідка оновила прогноз наступної хвилі."],
    "After Action Report": ["Післяопераційний звіт", "Сформовано підсумок завершеної бойової операції."],
    "Maintenance Assigned": ["Призначено обслуговування", "Установка проходить прискорене відновлення."],
    "Scenario Selected": ["Сценарій обрано", "Командний центр завантажив умови поточної операції."],
    "Intel Briefing": ["Розвідувальне зведення", "Зберігайте енергію, мораль і ремонтний резерв протягом операції."],
    "Simulation Scope": ["Межі симуляції", "Shieldline використовує умовні абстрактні механіки й дальності."],
  };
  const translated = copy[entry.title];
  return translated ? { ...entry, title: translated[0], body: translated[1] } : entry;
}

export function IntelLog({ game }: IntelLogProps) {
  return (
    <section className="intel-card" aria-label="Журнал розвідки">
      <div className="intel-heading">
        <Radio size={21} />
        <div>
          <span>Журнал розвідки</span>
          <strong>Погода: {weatherLabel[game.forecast.weather]}</strong>
        </div>
      </div>
      <article className="briefing-card">
        <strong>Оперативне зведення</strong>
        <p>Нові контакти з’являються постійно. Розміщуйте ППО вручну та стежте за зонами прикриття.</p>
        <span>Індекс тиску: {Math.round(game.wavePressure)}</span>
      </article>
      <div className="log-list">
        {game.log.slice(0, 14).map((rawEntry) => {
          const entry = localizedEntry(rawEntry);
          const visual = eventVisual(entry);
          const Icon = visual.Icon;
          return (
            <article className={`log-entry log-entry--${entry.tone} log-entry--${visual.kind}`} key={entry.id}>
              <Icon size={20} />
              <div>
                <strong>{entry.title}</strong>
                <p>{entry.body}</p>
              </div>
              <span>{entry.time}</span>
            </article>
          );
        })}
      </div>
    </section>
  );
}
