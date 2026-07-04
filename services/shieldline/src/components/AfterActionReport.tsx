import { ClipboardList } from "lucide-react";
import type { GameState } from "../types/game";

interface AfterActionReportProps {
  game: GameState;
}

export function AfterActionReport({ game }: AfterActionReportProps) {
  const active = game.liveThreats.length;
  const lowestNode = [...game.infrastructure].sort((left, right) => left.integrity - right.integrity)[0];
  const averageConfidence = active
    ? Math.round(game.liveThreats.reduce((sum, threat) => sum + threat.confidence, 0) / active)
    : 0;
  const recommendation = game.resources.ammo < 25
    ? "Conserve ammo and restore logistics."
    : game.resources.energy < 45
      ? "Prioritize energy resilience."
      : active > 6
        ? "Expand detection coverage."
        : "Maintain layered coverage.";

  return (
    <section className="aar-card" aria-label="After action report">
      <div className="aar-heading">
        <ClipboardList size={20} />
        <div>
          <strong>After-action report</strong>
          <span>Rolling live summary</span>
        </div>
      </div>
      <div className="aar-grid">
        <span><strong>{game.interceptions}</strong> Intercepts</span>
        <span><strong>{game.impacts}</strong> Impacts</span>
        <span><strong>{averageConfidence}%</strong> Intel accuracy</span>
        <span><strong>{lowestNode ? Math.round(lowestNode.integrity) : 0}%</strong> Weakest node</span>
      </div>
      <p>{recommendation}</p>
    </section>
  );
}
