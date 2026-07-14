import { ArrowLeft, Boxes, CloudFog, Gauge, Shield, Zap } from "lucide-react";
import { scenarios } from "../data/scenarios";

const scenarioIcons = [Shield, Zap, CloudFog, Boxes, Gauge];
const difficultyLabel = { training: "навчальна", standard: "стандартна", hard: "складна", endurance: "тривала" } as const;

interface ScenarioSelectionProps {
  onSelect: (scenarioId: string) => void;
  onBack: () => void;
}

export function ScenarioSelection({ onSelect, onBack }: ScenarioSelectionProps) {
  return (
    <section className="mode-screen" aria-label="Вибір сценарію Shieldline">
      <div className="mode-shell">
        <div className="mode-heading">
          <button className="scenario-back" type="button" onClick={onBack} aria-label="Повернутися до вибору режиму">
            <ArrowLeft size={20} />
          </button>
          <div>
            <h1>Оберіть сценарій</h1>
            <p>Кожен сценарій використовує умовні сектори, абстрактну логістику та збалансовані напрямки загроз.</p>
          </div>
        </div>
        <div className="scenario-grid">
          {scenarios.map((scenario, index) => {
            const Icon = scenarioIcons[index] || Shield;
            return (
              <button className="mode-card scenario-card" type="button" key={scenario.id} onClick={() => onSelect(scenario.id)}>
                <span className="mode-card__icon"><Icon size={24} /></span>
                <span className="mode-card__meta">{scenario.durationDays} циклів операції · {difficultyLabel[scenario.difficulty]}</span>
                <strong>{scenario.title}</strong>
                <em>{scenario.specialRules.join(" · ")}</em>
                <span>{scenario.description}</span>
                <small>
                  Бюджет {scenario.startingResources.budget} · БК {scenario.startingResources.ammo} · Мораль {scenario.startingResources.morale}%
                </small>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}
