import { AlertTriangle, CheckCircle2, Info, Radio } from "lucide-react";
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

function localizedEntry(entry: GameState["log"][number]) {
  if (entry.eventType === "launch" || entry.eventType === "detection" || /[А-Яа-яІіЇїЄє]/.test(entry.title)) return entry;
  if (entry.title.endsWith(" Placed")) return { ...entry, title: "ППО розміщено", body: "Установку додано до системи протиповітряної оборони." };
  const copy: Record<string, [string, string]> = {
    "Track Warning": ["Попередження про ціль", "На тактичній мапі з’явилася нова непідтверджена ціль."],
    "Intercept Confirmed": ["Перехоплення підтверджено", "Підрозділ ППО нейтралізував повітряну ціль."],
    Engagement: ["Бойова робота", "Установка ППО розпочала перехоплення цілі."],
    Impact: ["Влучання", "Ціль дісталася захищеної області."],
    "Threat Director": ["Оперативна обстановка", "Розвідка оновила прогноз наступної хвилі."],
    "After Action Report": ["Післяопераційний звіт", "Сформовано підсумок завершеної бойової операції."],
    "Maintenance Assigned": ["Призначено обслуговування", "Установка проходить прискорене відновлення."],
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
          <strong>Погода: {game.forecast.weather}</strong>
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
          const Icon = toneIcon[entry.tone];
          return (
            <article className={`log-entry log-entry--${entry.tone}`} key={entry.id}>
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
