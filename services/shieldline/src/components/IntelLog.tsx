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

export function IntelLog({ game }: IntelLogProps) {
  return (
    <section className="intel-card">
      <div className="intel-heading">
        <Radio size={21} />
        <div>
          <span>Intel Log</span>
          <strong>{game.forecast.weather} weather</strong>
        </div>
      </div>
      <article className="briefing-card">
        <strong>Intel Briefing</strong>
        <p>{game.forecast.vagueWarning}</p>
        <span>Political pressure index {Math.round(game.forecast.pressure)}</span>
      </article>
      <div className="log-list">
        {game.log.slice(0, 12).map((entry) => {
          const Icon = toneIcon[entry.tone];
          return (
            <article className={`log-entry log-entry--${entry.tone}`} key={entry.id}>
              <Icon size={20} />
              <div>
                <strong>{entry.title}</strong>
                <p>{entry.body}</p>
              </div>
              <span>Day {entry.day}</span>
            </article>
          );
        })}
      </div>
    </section>
  );
}
