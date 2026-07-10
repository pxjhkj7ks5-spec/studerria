import { ClipboardList } from "lucide-react";
import type { CSSProperties } from "react";
import { archetypeLabel } from "../game/threatDirector";
import type { GameState } from "../types/game";
import type { MissionRun, RankedResult } from "../domain/contracts";
import { formatNumber, t } from "../platform/i18n";

interface AfterActionReportProps {
  game: GameState;
  rankedResult?: RankedResult | null;
  authoritativeRun?: MissionRun | null;
}

export function AfterActionReport({ game, rankedResult, authoritativeRun }: AfterActionReportProps) {
  const report = game.afterActionReports[0];
  const fallbackRecommendation = game.resources.ammo < 25
    ? "Conserve ammo and restore logistics."
    : game.resources.energy < 45
      ? "Prioritize energy resilience."
      : game.liveThreats.length > 6
        ? "Expand detection coverage."
        : "Maintain layered coverage.";

  return (
    <section className="aar-card" aria-label="After action report">
      <div className="aar-heading">
        <ClipboardList size={20} />
        <div>
          <strong>{t("aar.title")}</strong>
          <span>{report ? `Cycle ${formatNumber(report.day)} · ${report.archetype ? archetypeLabel(report.archetype) : "contact cycle"}` : t("aar.pending")}</span>
        </div>
      </div>
      {authoritativeRun ? <div className="aar-section aar-section--ranked"><strong>{t("aar.server")}</strong><span>{formatNumber(authoritativeRun.interceptions)} {t("aar.intercepts")} · {formatNumber(authoritativeRun.impacts)} {t("aar.impacts")} · seed {authoritativeRun.seed.slice(-12)}</span></div> : null}
      {report ? (
        <>
          <p className="aar-summary">{report.situationSummary}</p>
          <div className="aar-grid">
            <span><strong>{report.threatOverview.totalTracks}</strong> Tracks</span>
            <span><strong>{report.threatOverview.confirmedThreats}</strong> Confirmed</span>
            <span><strong>{report.threatOverview.decoys}</strong> Decoys</span>
            <span><strong>{report.threatOverview.unidentifiedTracks}</strong> Unknown</span>
            <span><strong>{report.defensePerformance.interceptions}</strong> Intercepts</span>
            <span><strong>{report.defensePerformance.missedThreats}</strong> Missed</span>
          </div>
          <div className="aar-section">
            <strong>Defense Performance</strong>
            <span>Ammo spent {Math.round(report.defensePerformance.ammoSpent)} · readiness {Math.round(report.defensePerformance.averageReadinessChange)}%</span>
            <span>Strongest {report.defensePerformance.strongestUnit} · weakest area {report.defensePerformance.weakestCoverageArea}</span>
          </div>
          <div className="aar-section">
            <strong>Damage Report</strong>
            <span>{report.damageReport.damagedCities.length ? report.damageReport.damagedCities.join(", ") : "No new city damage reported"}</span>
            <span>Energy {Math.round(report.damageReport.systems.energy)}% · Logistics {Math.round(report.damageReport.systems.logistics)}% · Morale {Math.round(report.damageReport.systems.civilMorale)}%</span>
          </div>
          <div className="aar-section">
            <strong>Resource Changes</strong>
            <span>Budget {signed(report.resourceChanges.budget)} · Ammo {signed(report.resourceChanges.ammo)} · Energy {signed(report.resourceChanges.energy)}</span>
            <span>Morale {signed(report.resourceChanges.morale)} · Political {signed(report.resourceChanges.political)}</span>
          </div>
          <p>{report.recommendation}</p>
          {rankedResult ? <div className="aar-section aar-section--ranked"><strong>Ranked result</strong><span>#{rankedResult.entry.rank} · {rankedResult.entry.score} score · {rankedResult.challenge.title}</span></div> : null}
        </>
      ) : (
        authoritativeRun ? (
          <>
            <p className="aar-summary">Campaign outcome projected from simulation events sequence 1–{authoritativeRun.events.at(-1)?.sequence || 0}.</p>
            <div className="aar-grid">
              <span><strong>{formatNumber(authoritativeRun.interceptions)}</strong> {t("aar.intercepts")}</span>
              <span><strong>{formatNumber(authoritativeRun.impacts)}</strong> {t("aar.impacts")}</span>
              <span><strong>{formatNumber(authoritativeRun.ammoSpent)}</strong> {t("aar.ammo")}</span>
              <span><strong>{authoritativeRun.simVersion || "—"}</strong> {t("aar.version")}</span>
            </div>
            <div className="aar-sector-heatmap" aria-label="Campaign sector pressure heatmap">
              {Object.entries(authoritativeRun.sectorSummary).map(([sector, summary]) => (
                <span key={sector} style={{ "--sector-risk": `${Math.min(100, summary.pressure + summary.damage * 2)}%` } as CSSProperties}>
                  <b>{sector}</b><strong>{formatNumber(summary.pressure)}%</strong><small>{formatNumber(summary.damage)}% {t("aar.damage")}</small>
                </span>
              ))}
            </div>
            <p>{authoritativeRun.result === "victory" ? "Coverage held across every campaign sector." : authoritativeRun.result === "contained" ? "The attack was contained; reinforce damaged sectors before the next mission." : "Rebuild coverage and preserve the reserve before retrying this mission."}</p>
          </>
        ) : (
          <>
            <div className="aar-grid">
              <span><strong>{game.interceptions}</strong> Intercepts</span>
              <span><strong>{game.impacts}</strong> Impacts</span>
              <span><strong>{game.liveThreats.length}</strong> Active tracks</span>
              <span><strong>{Math.round(game.wavePressure)}</strong> Pressure</span>
            </div>
            <p>{fallbackRecommendation}</p>
          </>
        )
      )}
    </section>
  );
}

function signed(value: number) {
  const rounded = Math.round(value);
  return `${rounded >= 0 ? "+" : ""}${rounded}`;
}
