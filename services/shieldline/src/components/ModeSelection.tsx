import { Activity, Clock, GraduationCap, Infinity, Shield } from "lucide-react";
import { campaignModes } from "../data/campaignModes";
import type { CampaignMode } from "../types/game";
import { BrandMark } from "./BrandMark";

const modeIcons: Record<CampaignMode, typeof Shield> = {
  training: GraduationCap,
  "seven-day": Clock,
  crisis: Activity,
  sandbox: Infinity,
};

interface ModeSelectionProps {
  onSelect: (mode: CampaignMode) => void;
}

export function ModeSelection({ onSelect }: ModeSelectionProps) {
  return (
    <section className="mode-screen" data-audio-scope="player" aria-label="Вибір режиму кампанії Shieldline">
      <div className="mode-shell">
        <div className="mode-heading">
          <div className="mode-mark">
            <BrandMark size={40} />
          </div>
          <div>
            <h1>Shieldline</h1>
            <p>Оберіть профіль операції. Усі сценарії використовують умовні сектори, абстрактні дальності та ігровий баланс.</p>
          </div>
        </div>
        <div className="mode-grid">
          {campaignModes.map((mode) => {
            const Icon = modeIcons[mode.id];
            return (
              <button className="mode-card" type="button" key={mode.id} onClick={() => onSelect(mode.id)}>
                <span className="mode-card__icon"><Icon size={24} /></span>
                <span className="mode-card__meta">{mode.durationLabel}</span>
                <strong>{mode.title}</strong>
                <em>{mode.posture}</em>
                <span>{mode.description}</span>
                <small>
                  Бюджет {mode.resources.budget} · БК {mode.resources.ammo} · Мораль {mode.resources.morale}%
                </small>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}
