import { ArrowLeft, Boxes, CloudFog, Gauge, Shield, Zap } from "lucide-react";
import { scenarios } from "../data/scenarios";

const scenarioIcons = [Shield, Zap, CloudFog, Boxes, Gauge];

interface ScenarioSelectionProps {
  onSelect: (scenarioId: string) => void;
  onBack: () => void;
}

export function ScenarioSelection({ onSelect, onBack }: ScenarioSelectionProps) {
  return (
    <section className="mode-screen" aria-label="Shieldline scenario selection">
      <div className="mode-shell">
        <div className="mode-heading">
          <button className="scenario-back" type="button" onClick={onBack} aria-label="Back to mode selection">
            <ArrowLeft size={20} />
          </button>
          <div>
            <h1>Choose Scenario</h1>
            <p>Each scenario uses fictional sectors, abstract logistics, and game-balanced threat direction.</p>
          </div>
        </div>
        <div className="scenario-grid">
          {scenarios.map((scenario, index) => {
            const Icon = scenarioIcons[index] || Shield;
            return (
              <button className="mode-card scenario-card" type="button" key={scenario.id} onClick={() => onSelect(scenario.id)}>
                <span className="mode-card__icon"><Icon size={24} /></span>
                <span className="mode-card__meta">{scenario.durationDays} operation cycles · {scenario.difficulty}</span>
                <strong>{scenario.title}</strong>
                <em>{scenario.specialRules.join(" · ")}</em>
                <span>{scenario.description}</span>
                <small>
                  Budget {scenario.startingResources.budget} · Ammo {scenario.startingResources.ammo} · Morale {scenario.startingResources.morale}%
                </small>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}
