import { ArrowLeft, ArrowRight, ChevronDown, ClipboardList, LogOut, RotateCcw, Shield, Warehouse } from "lucide-react";
import { useEffect, useRef } from "react";
import { archetypeLabel } from "../game/threatDirector";
import { buildAfterActionPresentation } from "../game/campaignPresentation";
import type { GameState } from "../types/game";
import type { MissionRun, RankedResult } from "../domain/contracts";
import { formatNumber } from "../platform/i18n";

interface AfterActionReportProps {
  game: GameState;
  rankedResult?: RankedResult | null;
  authoritativeRun?: MissionRun | null;
  variant?: "panel" | "fullscreen";
  onInspectMap?: () => void;
  onExit?: () => void;
  onContinueCampaign?: () => void;
  onRetryCampaign?: () => void;
}

export function AfterActionReport({ game, rankedResult, authoritativeRun, variant = "panel", onInspectMap, onExit, onContinueCampaign, onRetryCampaign }: AfterActionReportProps) {
  const report = game.afterActionReports[0];
  const view = buildAfterActionPresentation(game, authoritativeRun);
  const { campaignResult } = view;
  const reportRef = useRef<HTMLElement | null>(null);
  const damagedCities = report?.damageReport.damagedCities || [];
  const depotNeedsAttention = Boolean(campaignResult && (campaignResult.depotHealth < 100 || campaignResult.depotProduced || campaignResult.depotLost));
  const defenseNeedsAttention = Boolean(report && (report.defensePerformance.missedThreats > 0 || Math.abs(report.defensePerformance.averageReadinessChange) >= 1));
  const nextMissionIndex = game.campaign && !game.campaign.completed ? Math.min(5, game.campaign.missionIndex + 1) : null;
  const primaryAction = campaignResult?.outcome === "defeat" && onRetryCampaign
    ? { label: "Повторити місію", icon: RotateCcw, action: onRetryCampaign }
    : game.campaign?.intermission && nextMissionIndex && onContinueCampaign
      ? { label: `До місії ${nextMissionIndex}`, icon: ArrowRight, action: onContinueCampaign }
      : game.campaign?.completed && onExit
        ? { label: "Завершити кампанію", icon: ArrowRight, action: onExit }
        : null;
  const PrimaryActionIcon = primaryAction?.icon;

  useEffect(() => {
    if (variant !== "fullscreen") return undefined;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    reportRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || !onInspectMap) return;
      event.preventDefault();
      onInspectMap();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      previousFocus?.focus();
    };
  }, [onInspectMap, variant]);

  return (
    <section ref={reportRef} tabIndex={variant === "fullscreen" ? -1 : undefined} className={`aar-card aar-card--${variant} aar-card--${view.outcome}`} aria-label="Післяопераційний звіт">
      <header className="aar-heading">
        <ClipboardList size={22} />
        <div>
          <span className="aar-eyebrow">Післяопераційний звіт</span>
          <strong className="aar-outcome">{view.outcomeLabel}</strong>
          <h1>{view.title}</h1>
          <p>{view.objectiveSummary}</p>
        </div>
      </header>

      <section className="aar-key-metrics" aria-label="Ключові результати">
        <Metric value={`${formatNumber(view.interceptions)}/${formatNumber(view.totalTargets)}`} label="Збито" />
        <Metric value={formatNumber(view.impacts)} label="Влучань" critical={view.impacts > 0} />
        <Metric value={`${formatNumber(view.minimumCityHp)}%`} label="Найнижчий HP міста" critical={view.minimumCityHp <= 30} />
        <Metric value={view.depotHealth === null ? "—" : `${formatNumber(view.depotHealth)}% · ${formatNumber(view.depotStock || 0)} БК`} label="Склад БК" critical={(view.depotHealth || 100) <= 30} />
      </section>

      {campaignResult ? (
        <section className="aar-economy" aria-label="Економіка місії">
          <header><span>Економіка місії</span><strong>{formatNumber(view.finalWallet || 0)} млн ₴</strong><small>Фінальний гаманець</small></header>
          <div>{view.economy.map((line) => <span className={line.tone ? `is-${line.tone}` : ""} key={line.label}><small>{line.label}</small><strong>{line.value > 0 ? "+" : ""}{formatNumber(line.value)} млн ₴</strong></span>)}</div>
        </section>
      ) : null}

      {(damagedCities.length || depotNeedsAttention || defenseNeedsAttention) ? <section className="aar-notables" aria-label="Важливі наслідки">
        {damagedCities.length ? <div><Shield size={18} /><span><strong>Пошкоджені міста</strong><small>{damagedCities.join(", ")}</small></span></div> : null}
        {depotNeedsAttention && campaignResult ? <div><Warehouse size={18} /><span><strong>Логістика складу</strong><small>Вироблено {formatNumber(campaignResult.depotProduced)} БК · втрачено {formatNumber(campaignResult.depotLost)} БК · стан {formatNumber(campaignResult.depotHealth)}%</small></span></div> : null}
        {defenseNeedsAttention && report ? <div><Shield size={18} /><span><strong>Стан оборони</strong><small>Готовність {formatNumber(report.defensePerformance.averageReadinessChange)}% · пропущено {formatNumber(report.defensePerformance.missedThreats)}</small></span></div> : null}
      </section> : null}

      <details className="aar-details">
        <summary><span>Детальна статистика</span><ChevronDown size={16} /></summary>
        <div className="aar-details__grid">
          <Detail label="Усього контактів" value={report ? formatNumber(report.threatOverview.totalTracks) : formatNumber(view.totalTargets)} />
          <Detail label="Підтверджені цілі" value={report ? formatNumber(report.threatOverview.confirmedThreats) : "—"} />
          <Detail label="Приманки" value={report ? formatNumber(report.threatOverview.decoys) : "—"} />
          <Detail label="Невідомі контакти" value={report ? formatNumber(report.threatOverview.unidentifiedTracks) : "—"} />
          <Detail label="Витрачено БК" value={report ? formatNumber(report.defensePerformance.ammoSpent) : authoritativeRun ? formatNumber(authoritativeRun.ammoSpent) : "—"} />
          <Detail label="Зміна готовності" value={report ? `${formatNumber(report.defensePerformance.averageReadinessChange)}%` : "—"} />
          <Detail label="Найсильніша система" value={report?.defensePerformance.strongestUnit || "—"} />
          <Detail label="Слабка зона" value={report?.defensePerformance.weakestCoverageArea || "—"} />
          <Detail label="Зерно симуляції" value={authoritativeRun?.seed ? authoritativeRun.seed.slice(-12) : "—"} mono />
          <Detail label="Версія симуляції" value={authoritativeRun?.simVersion || "—"} mono />
        </div>
        {report?.archetype ? <p>Профіль атаки: {archetypeLabel(report.archetype)}.</p> : null}
        {rankedResult ? <p>Рейтинг: #{rankedResult.entry.rank} · {rankedResult.entry.score} балів · {rankedResult.challenge.title}.</p> : null}
      </details>

      {variant === "fullscreen" ? (
        <footer className="aar-actions">
          {primaryAction && PrimaryActionIcon ? <button className="aar-action aar-action--primary" type="button" onClick={primaryAction.action}><PrimaryActionIcon size={17} />{primaryAction.label}</button> : null}
          {onInspectMap ? <button className="aar-action aar-action--secondary" type="button" onClick={onInspectMap}><ArrowLeft size={17} /> Оглянути мапу</button> : null}
          {onExit && !game.campaign?.completed ? <button className="aar-action aar-action--tertiary" type="button" onClick={onExit}><LogOut size={17} /> До головного меню</button> : null}
        </footer>
      ) : primaryAction && PrimaryActionIcon ? (
        <footer className="aar-actions aar-actions--inline"><button className="aar-action aar-action--primary" type="button" onClick={primaryAction.action}><PrimaryActionIcon size={17} />{primaryAction.label}</button></footer>
      ) : null}
    </section>
  );
}

function Metric({ value, label, critical = false }: { value: string; label: string; critical?: boolean }) {
  return <span className={critical ? "is-critical" : ""}><strong>{value}</strong><small>{label}</small></span>;
}

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <span><small>{label}</small><strong className={mono ? "is-mono" : ""}>{value}</strong></span>;
}
