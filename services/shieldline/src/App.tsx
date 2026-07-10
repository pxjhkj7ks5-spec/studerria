import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, AlertTriangle, ClipboardList, Crosshair, Layers, Menu, Radio, RotateCcw, Settings, Shield, SlidersHorizontal, X, Zap } from "lucide-react";
import { AfterActionReport } from "./components/AfterActionReport";
import { ControlZoneAdmin } from "./components/ControlZoneAdmin";
import { IntelLog } from "./components/IntelLog";
import { MapLegend } from "./components/MapLegend";
import { ModeSelection } from "./components/ModeSelection";
import { PlanningActionsPanel } from "./components/PlanningActionsPanel";
import { ResourceBar } from "./components/ResourceBar";
import { ScenarioSelection } from "./components/ScenarioSelection";
import { TacticalMap } from "./components/TacticalMap";
import { TutorialOverlay } from "./components/TutorialOverlay";
import { UnitRail } from "./components/UnitRail";
import { CommandApp } from "./components/CommandApp";
import { apiGameRepository } from "./data/apiGameRepository";
import { getCampaignModeDefinition } from "./data/campaignModes";
import { defenseReadinessForMode, getGameModeRuntimePolicy } from "./data/gameModes";
import { campaignMissions } from "./data/missions";
import { getScenario } from "./data/scenarios";
import { getUnitDefinition } from "./data/units";
import { projectCampaignRun } from "./game/campaignProjection";
import { useGameStore } from "./store/useGameStore";
import { bindTelegramBackButton, bindTelegramBottomButton } from "./platform/telegramShell";
import { formatNumber, formatSimulationEvent, t } from "./platform/i18n";
import { trackAnalytics } from "./platform/analytics";
import type { CampaignStatus, DefenseBattery, MapMode, ThreatKind, UnitDefinition, UnitKind } from "./types/game";
import type { CampaignProgress, DailyDefensePlan, GameModeId, MissionRun, OperationPhase, RankedResult, SimulationEvent } from "./domain/contracts";

const mapModes: Array<{ id: MapMode; label: string }> = [
  { id: "live", label: t("layer.live") },
  { id: "threats", label: t("layer.threats") },
  { id: "coverage", label: t("layer.coverage") },
  { id: "logistics", label: t("layer.logistics") },
];

const threatLabels: Array<{ kind: ThreatKind; label: string }> = [
  { kind: "geran2", label: "Geran" },
  { kind: "gerbera", label: "Gerbera" },
  { kind: "kh101", label: "X-101" },
  { kind: "iskander", label: "OTRK" },
];

const SIMULATION_TICK_MS = 300;
const CAMPAIGN_SESSION_KEY = "shieldline-campaign-operation-v1";

interface PersistedCampaignOperation {
  runId: string;
  missionId: string;
  phase: OperationPhase;
  playbackMs: number;
  updatedAt: number;
  speed: number;
}

function coOpSectorForCity(cityId: string) {
  if (["chernihiv", "sumy", "kyiv", "zhytomyr", "rivne", "lutsk"].includes(cityId)) return "north";
  if (["kharkiv", "dnipro", "zaporizhzhia", "poltava", "kryvyi-rih"].includes(cityId)) return "east";
  if (["odesa", "mykolaiv", "kropyvnytskyi", "cherkasy"].includes(cityId)) return "south";
  return "west";
}

function defensePlanFromBatteries(batteries: DefenseBattery[]): DailyDefensePlan {
  const assets = batteries.map((battery) => ({ id: battery.id, kind: battery.kind, cityId: battery.assignedCityId, readiness: battery.readiness, position: battery.position }));
  return { assetCount: assets.length, radarCount: assets.filter((asset) => asset.kind === "radar").length, kineticCount: assets.filter((asset) => !["radar", "ew"].includes(asset.kind)).length, averageReadiness: assets.length ? assets.reduce((sum, asset) => sum + asset.readiness, 0) / assets.length : 0, assets };
}

type ActivePanel = "layers" | "units" | "planning" | "intel" | "report" | "settings";

const panelItems: Array<{ id: ActivePanel; label: string; icon: typeof Layers }> = [
  { id: "layers", label: t("panel.layers"), icon: Layers },
  { id: "units", label: t("panel.units"), icon: Crosshair },
  { id: "planning", label: t("panel.planning"), icon: SlidersHorizontal },
  { id: "intel", label: t("panel.intel"), icon: Radio },
  { id: "report", label: t("panel.report"), icon: ClipboardList },
  { id: "settings", label: t("panel.settings"), icon: Settings },
];

const panelTitle: Record<ActivePanel, string> = {
  layers: t("panel.layers"),
  units: t("panel.units"),
  planning: t("panel.planning"),
  intel: t("panel.intel"),
  report: t("panel.report"),
  settings: t("panel.settings"),
};

function formatAmmo(current: number | "infinite", capacity: number | "infinite") {
  if (capacity === "infinite" || current === "infinite") return "inf";
  return `${current}/${capacity}`;
}

function formatSeconds(ms: number) {
  if (ms <= 0) return "ready";
  return `${Math.ceil(ms / 1000)}s`;
}

export default function App() {
  const isAdminRoute = typeof window !== "undefined" && window.location.pathname.replace(/\/+$/, "").endsWith("/admin");
  if (isAdminRoute) {
    return <ControlZoneAdmin />;
  }
  const legacyRequested = typeof window !== "undefined" && new URLSearchParams(window.location.search).get("legacy") === "1";
  if (!legacyRequested) {
    return <CommandApp />;
  }

  const game = useGameStore((state) => state.game);
  const campaignMode = useGameStore((state) => state.campaignMode);
  const pendingCampaignMode = useGameStore((state) => state.pendingCampaignMode);
  const mapMode = useGameStore((state) => state.mapMode);
  const tutorialDismissed = useGameStore((state) => state.tutorialDismissed);
  const selectCampaignMode = useGameStore((state) => state.selectCampaignMode);
  const selectScenario = useGameStore((state) => state.selectScenario);
  const clearScenarioSelection = useGameStore((state) => state.clearScenarioSelection);
  const returnToModeSelect = useGameStore((state) => state.returnToModeSelect);
  const setMapMode = useGameStore((state) => state.setMapMode);
  const dismissTutorial = useGameStore((state) => state.dismissTutorial);
  const resetCampaign = useGameStore((state) => state.resetCampaign);
  const advanceOperation = useGameStore((state) => state.advanceOperation);
  const startOperation = useGameStore((state) => state.startOperation);
  const removeSelectedBattery = useGameStore((state) => state.removeSelectedBattery);
  const startSelectedBatteryMaintenance = useGameStore((state) => state.startSelectedBatteryMaintenance);
  const selectedBatteryId = useGameStore((state) => state.selectedBatteryId);
  const placementKind = useGameStore((state) => state.placementKind);
  const activeGameMode = useGameStore((state) => state.activeGameMode);
  const operationPhase = useGameStore((state) => state.operationPhase);
  const simulationSpeed = useGameStore((state) => state.simulationSpeed);
  const [confirmReset, setConfirmReset] = useState(false);
  const [activePanel, setActivePanel] = useState<ActivePanel | null>("units");
  const [rankedResult, setRankedResult] = useState<RankedResult | null>(null);
  const [authoritativeRun, setAuthoritativeRun] = useState<MissionRun | null>(null);
  const [campaignProgress, setCampaignProgress] = useState<CampaignProgress | null>(null);
  const [isResolving, setIsResolving] = useState(false);
  const [campaignRuntimePhase, setCampaignRuntimePhase] = useState<OperationPhase>("planning");
  const [campaignCountdownMs, setCampaignCountdownMs] = useState(0);
  const [campaignPlaybackMs, setCampaignPlaybackMs] = useState(0);
  const coOpSyncedBatteryIds = useRef(new Set<string>());
  const campaignSyncedBatteryIds = useRef(new Set<string>());
  const dailySavedPlanRef = useRef<string | null>(null);
  const completedTrackedRunRef = useRef<string | null>(null);
  const selectedBattery = game.batteries.find((battery) => battery.id === selectedBatteryId) || null;
  const selectedUnit = selectedBattery ? getUnitDefinition(selectedBattery.kind) : null;
  const modeDefinition = campaignMode ? getCampaignModeDefinition(campaignMode) : null;
  const scenario = getScenario(game.scenarioId);
  const lastTickRef = useRef<number | null>(null);
  const accumulatorRef = useRef(0);
  const revealedThreats = game.liveThreats.filter((threat) => threat.revealed).length;
  const tacticalMode = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("mode") : null;
  const resolvedMode = (activeGameMode || tacticalMode || "training") as GameModeId;
  const runtimePolicy = getGameModeRuntimePolicy(resolvedMode);
  const defenseReadiness = defenseReadinessForMode(resolvedMode, game.batteries.map((battery) => battery.kind));
  const coOpSession = (() => {
    if (typeof window === "undefined" || tacticalMode !== "co-op-command") return null;
    try { return JSON.parse(window.sessionStorage.getItem("shieldline-coop-session") || "null") as { roomId: string; sectorId: string } | null; } catch { return null; }
  })();
  const activeMission = campaignMissions.find((mission) => mission.id === campaignProgress?.currentMissionId) || campaignMissions[0];
  const activeMissionTitle = t(activeMission.id === "campaign-night-02" ? "mission.2" : activeMission.id === "campaign-night-03" ? "mission.3" : "mission.1");
  const isAuthoritativeCampaign = tacticalMode === "campaign";
  const effectiveOperationPhase = isAuthoritativeCampaign ? campaignRuntimePhase : operationPhase;
  const campaignEndMs = authoritativeRun?.events.at(-1)?.occurredAtMs || 0;
  const campaignProjection = useMemo(
    () => projectCampaignRun(isAuthoritativeCampaign ? authoritativeRun : null, campaignPlaybackMs),
    [authoritativeRun, campaignPlaybackMs, isAuthoritativeCampaign],
  );
  const displayGame = useMemo(
    () => campaignProjection ? { ...game, interceptions: campaignProjection.interceptions, impacts: campaignProjection.impacts } : game,
    [campaignProjection, game],
  );
  const displayRevealedThreats = campaignProjection ? campaignProjection.liveThreats.filter((threat) => threat.revealed).length : revealedThreats;
  const returnToCommandModes = () => {
    const url = new URL(window.location.href);
    url.search = "";
    window.location.assign(url.toString());
  };
  const startCampaignOperation = async () => {
    if (!defenseReadiness.ready || isResolving) return;
    setIsResolving(true);
    setCampaignRuntimePhase("countdown");
    setCampaignCountdownMs(5_000);
    setCampaignPlaybackMs(0);
    try {
      const runSeed = `campaign-${activeMission.id}-${crypto.randomUUID()}`;
      const result = await apiGameRepository.createOperation({
        modeId: "campaign",
        missionId: activeMission.id,
        seed: runSeed,
        plan: defensePlanFromBatteries(game.batteries),
      });
      setAuthoritativeRun(result.run);
      trackAnalytics("campaign.operation.started", { runId: result.runId, missionId: activeMission.id, simVersion: result.simVersion });
    } catch {
      setCampaignRuntimePhase("planning");
      setCampaignCountdownMs(0);
    } finally {
      setIsResolving(false);
    }
  };
  const handleStartOperation = () => {
    if (isAuthoritativeCampaign) void startCampaignOperation();
    else startOperation();
  };
  const handleResetOperation = () => {
    if (isAuthoritativeCampaign) {
      window.localStorage.removeItem(CAMPAIGN_SESSION_KEY);
      setAuthoritativeRun(null);
      setCampaignRuntimePhase("planning");
      setCampaignCountdownMs(0);
      setCampaignPlaybackMs(0);
    }
    resetCampaign();
  };

  useEffect(() => bindTelegramBackButton(returnToCommandModes), []);

  useEffect(() => bindTelegramBottomButton({
    text: t("operation.start"),
    enabled: defenseReadiness.ready,
    visible: runtimePolicy.execution === "live" && runtimePolicy.start !== "auto-checklist" && effectiveOperationPhase === "planning",
    onClick: handleStartOperation,
  }), [defenseReadiness.ready, effectiveOperationPhase, runtimePolicy.execution, runtimePolicy.start, isAuthoritativeCampaign, isResolving, game.batteries, activeMission.id]);

  useEffect(() => {
    if (isAuthoritativeCampaign || !campaignMode || runtimePolicy.execution !== "live" || (operationPhase !== "running" && operationPhase !== "countdown")) return undefined;
    let frameId = 0;
    const frame = (timestamp: number) => {
      if (lastTickRef.current === null) {
        lastTickRef.current = timestamp;
      }
      const delta = timestamp - lastTickRef.current;
      lastTickRef.current = timestamp;
      accumulatorRef.current += delta;
      if (accumulatorRef.current >= SIMULATION_TICK_MS) {
        advanceOperation(accumulatorRef.current);
        accumulatorRef.current = 0;
      }
      frameId = window.requestAnimationFrame(frame);
    };
    frameId = window.requestAnimationFrame(frame);
    return () => window.cancelAnimationFrame(frameId);
  }, [advanceOperation, campaignMode, isAuthoritativeCampaign, operationPhase, runtimePolicy.execution]);

  useEffect(() => {
    lastTickRef.current = null;
    accumulatorRef.current = 0;
  }, [resolvedMode, operationPhase]);

  useEffect(() => {
    if (!isAuthoritativeCampaign || (campaignRuntimePhase !== "countdown" && campaignRuntimePhase !== "running")) return undefined;
    let last = performance.now();
    const timer = window.setInterval(() => {
      const now = performance.now();
      const delta = Math.max(0, now - last);
      last = now;
      if (campaignRuntimePhase === "countdown") {
        setCampaignCountdownMs((remaining) => {
          const next = Math.max(0, remaining - delta);
          if (next === 0 && authoritativeRun) setCampaignRuntimePhase("running");
          return next;
        });
        return;
      }
      setCampaignPlaybackMs((current) => Math.min(campaignEndMs, current + delta * simulationSpeed));
    }, 100);
    return () => window.clearInterval(timer);
  }, [authoritativeRun, campaignEndMs, campaignRuntimePhase, isAuthoritativeCampaign, simulationSpeed]);

  useEffect(() => {
    if (!isAuthoritativeCampaign || campaignRuntimePhase !== "running" || !campaignEndMs || campaignPlaybackMs < campaignEndMs) return;
    setCampaignRuntimePhase("completed");
    setActivePanel("report");
    if (authoritativeRun && completedTrackedRunRef.current !== authoritativeRun.id) {
      completedTrackedRunRef.current = authoritativeRun.id;
      trackAnalytics("campaign.operation.completed", { runId: authoritativeRun.id, missionId: authoritativeRun.missionId, result: authoritativeRun.result, interceptions: authoritativeRun.interceptions, impacts: authoritativeRun.impacts });
    }
  }, [authoritativeRun, campaignEndMs, campaignPlaybackMs, campaignRuntimePhase, isAuthoritativeCampaign]);

  useEffect(() => {
    if (!isAuthoritativeCampaign) return;
    const raw = window.localStorage.getItem(CAMPAIGN_SESSION_KEY);
    if (!raw) return;
    try {
      const saved = JSON.parse(raw) as PersistedCampaignOperation;
      void apiGameRepository.getOperation(saved.runId).then((run) => {
        if (!run) {
          window.localStorage.removeItem(CAMPAIGN_SESSION_KEY);
          return;
        }
        const end = run.events.at(-1)?.occurredAtMs || 0;
        const elapsedSinceSave = saved.phase === "running" ? Math.max(0, Date.now() - saved.updatedAt) * Math.max(1, saved.speed) : 0;
        const playback = Math.min(end, Math.max(0, saved.playbackMs + elapsedSinceSave));
        setAuthoritativeRun(run);
        setCampaignPlaybackMs(playback);
        setCampaignCountdownMs(0);
        setCampaignRuntimePhase(playback >= end ? "completed" : saved.phase === "countdown" ? "running" : saved.phase);
        trackAnalytics("campaign.reconnected", { runId: run.id, phase: saved.phase, playbackMs: Math.round(playback) });
      }).catch(() => undefined);
    } catch {
      window.localStorage.removeItem(CAMPAIGN_SESSION_KEY);
    }
  }, [isAuthoritativeCampaign]);

  useEffect(() => {
    if (!isAuthoritativeCampaign || !authoritativeRun) return;
    const saved: PersistedCampaignOperation = {
      runId: authoritativeRun.id,
      missionId: authoritativeRun.missionId,
      phase: campaignRuntimePhase,
      playbackMs: campaignPlaybackMs,
      updatedAt: Date.now(),
      speed: simulationSpeed,
    };
    window.localStorage.setItem(CAMPAIGN_SESSION_KEY, JSON.stringify(saved));
  }, [authoritativeRun, campaignPlaybackMs, campaignRuntimePhase, isAuthoritativeCampaign, simulationSpeed]);

  useEffect(() => {
    if (tacticalMode !== "campaign") return;
    void apiGameRepository.getCampaignProgress().then(setCampaignProgress).catch(() => setCampaignProgress(null));
  }, [tacticalMode, authoritativeRun?.id]);

  useEffect(() => {
    if (tacticalMode !== "daily-defense" || !game.batteries.length) return;
    const plan = defensePlanFromBatteries(game.batteries);
    const fingerprint = JSON.stringify(plan);
    if (dailySavedPlanRef.current === fingerprint) return;
    const timeout = window.setTimeout(() => {
      void apiGameRepository.saveDailyCity(plan).then(() => { dailySavedPlanRef.current = fingerprint; }).catch(() => undefined);
    }, 450);
    return () => window.clearTimeout(timeout);
  }, [game.batteries, tacticalMode]);

  useEffect(() => {
    if (tacticalMode !== "co-op-command" || !coOpSession) return;
    for (const battery of game.batteries) {
      if (coOpSyncedBatteryIds.current.has(battery.id)) continue;
      const sectorId = coOpSectorForCity(battery.assignedCityId);
      if (sectorId !== coOpSession.sectorId) continue;
      coOpSyncedBatteryIds.current.add(battery.id);
      void apiGameRepository.sendCoOpCommand(coOpSession.roomId, sectorId as "north" | "south" | "east" | "west", { type: "asset.place", payload: { batteryId: battery.id, kind: battery.kind, cityId: battery.assignedCityId, readiness: Math.round(battery.readiness), position: battery.position } }).catch(() => {
        coOpSyncedBatteryIds.current.delete(battery.id);
      });
    }
  }, [coOpSession, game.batteries, tacticalMode]);

  useEffect(() => {
    if (!tacticalMode || tacticalMode === "co-op-command") return;
    for (const battery of game.batteries) {
      if (campaignSyncedBatteryIds.current.has(battery.id)) continue;
      campaignSyncedBatteryIds.current.add(battery.id);
      void apiGameRepository.recordCampaignCommand({ type: "asset.place", payload: { batteryId: battery.id, kind: battery.kind, cityId: battery.assignedCityId, readiness: Math.round(battery.readiness), position: battery.position } }).catch(() => campaignSyncedBatteryIds.current.delete(battery.id));
      trackAnalytics("campaign.asset.placed", { batteryId: battery.id, kind: battery.kind, cityId: battery.assignedCityId });
    }
  }, [game.batteries, tacticalMode]);

  const resolveAuthoritativeOperation = async () => {
    if (!game.batteries.length) return;
    setIsResolving(true);
    try {
      if (tacticalMode === "ranked-challenge") {
        const challenge = await apiGameRepository.getRankedChallenge();
        const result = await apiGameRepository.submitRankedChallenge(challenge.id, defensePlanFromBatteries(game.batteries));
        setRankedResult(result);
        setAuthoritativeRun(result.run);
      } else if (tacticalMode === "co-op-command" && coOpSession) {
        const result = await apiGameRepository.resolveCoOpRoom(coOpSession.roomId);
        setAuthoritativeRun(result.run);
      } else {
        const seed = `${tacticalMode || "campaign"}-${activeMission.id}-${new Date().toISOString().slice(0, 10)}`;
        const run = await apiGameRepository.runMission(activeMission, seed, defensePlanFromBatteries(game.batteries));
        setAuthoritativeRun(run);
      }
      setActivePanel("report");
    } finally {
      setIsResolving(false);
    }
  };

  if (!campaignMode && pendingCampaignMode) {
    return <ScenarioSelection onSelect={selectScenario} onBack={clearScenarioSelection} />;
  }

  if (!campaignMode) {
    return <ModeSelection onSelect={selectCampaignMode} />;
  }

  return (
    <main className={`shell shell--map-first ${activePanel ? "shell--drawer-open" : "shell--drawer-closed"}`} aria-label="Shieldline real-time defense simulation">
      <nav className="app-rail" aria-label="Shieldline panels">
        <button className="rail-button rail-button--menu" type="button" aria-label="Back to command modes" onClick={returnToCommandModes}>
          <Menu size={24} />
        </button>
        <div className="rail-brand" aria-hidden="true">
          <Shield size={24} />
        </div>
        <div className="rail-button-stack">
          {panelItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={`rail-button ${activePanel === item.id ? "rail-button--active" : ""}`}
                type="button"
                key={item.id}
                onClick={() => {
                  if (item.id === "report" && authoritativeRun) trackAnalytics("campaign.replay.opened", { runId: authoritativeRun.id, source: "navigation" });
                  setActivePanel((current) => (current === item.id ? null : item.id));
                }}
                aria-label={item.label}
                aria-pressed={activePanel === item.id}
                title={item.label}
              >
                <Icon size={21} />
              </button>
            );
          })}
        </div>
      </nav>

      <section className={`map-stage map-stage--${mapMode} ${placementKind ? "map-stage--placing" : ""}`} aria-label="Live defense map">
        <TacticalMap projection={campaignProjection} />
        <header className="map-status-strip" aria-label="Campaign status">
          <div className="strip-brand">
            <Shield size={22} />
            <div>
              <h1>Shieldline</h1>
              <span>{tacticalMode === "campaign" ? `${activeMissionTitle} · ${t("stream.title")}` : `${scenario.title} · ${modeDefinition?.title || "Live defense"} · ${game.cyclePhase}`}</span>
            </div>
          </div>
          <ResourceBar game={displayGame} simulationSpeed={simulationSpeed} operationPhase={effectiveOperationPhase} />
        </header>
        <MapLegend mode={mapMode} />
      </section>

      {activePanel ? (
        <aside className={`command-drawer command-drawer--${activePanel}`} aria-label={`${panelTitle[activePanel]} panel`}>
          <div className="drawer-header">
            <div>
              <span>Shieldline</span>
              <strong>{panelTitle[activePanel]}</strong>
            </div>
            <button className="drawer-close" type="button" aria-label={t("action.close")} onClick={() => setActivePanel(null)}>
              <X size={18} />
            </button>
          </div>
          {activePanel === "layers" ? (
            <section className="drawer-section">
              <div className="panel-layer-list">
                {mapModes.map((mode) => (
                  <button
                    className={`nav-pill ${mapMode === mode.id ? "nav-pill--active" : ""}`}
                    type="button"
                    key={mode.id}
                    onClick={() => setMapMode(mode.id)}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
              <div className="live-stats live-stats--drawer" aria-label="Live defense telemetry">
                <span><strong>{formatNumber(game.day)}</strong> {t("stats.cycle")}</span>
                <span><strong>{formatNumber(displayRevealedThreats)}</strong> {t("stats.revealed")}</span>
                <span><strong>{formatNumber(displayGame.interceptions)}</strong> {t("stats.interceptions")}</span>
                <span><strong>{formatNumber(displayGame.impacts)}</strong> {t("stats.impacts")}</span>
                <span><strong>{formatNumber(Math.round(game.wavePressure))}</strong> {t("stats.pressure")}</span>
                <span><strong>{formatNumber(game.logistics.resupplyDelayDays)}</strong> {t("stats.supply")}</span>
              </div>
              {selectedBattery ? (
                <SelectedUnitPanel
                  selectedBattery={selectedBattery}
                  selectedUnit={selectedUnit}
                  onMaintain={startSelectedBatteryMaintenance}
                  onRecall={removeSelectedBattery}
                />
              ) : (
                <LiveStatusPanel placementKind={placementKind} placementWarning={game.placementWarning} />
              )}
            </section>
          ) : null}
          {activePanel === "units" ? <UnitRail /> : null}
          {activePanel === "planning" ? (
            <section className="drawer-section">
              <PlanningActionsPanel />
              {game.resources.ammo < 15 ? <AmmoLowCard /> : null}
            </section>
          ) : null}
          {activePanel === "intel" ? (
            <section className="drawer-section">
              {campaignProjection ? <CampaignEventLog events={campaignProjection.visibleEvents} /> : <IntelLog game={game} />}
              {game.status !== "active" ? <CampaignStatusCard status={game.status} statusReason={game.statusReason} /> : null}
            </section>
          ) : null}
          {activePanel === "report" ? (
            <section className="drawer-section">
              <AfterActionReport game={game} rankedResult={rankedResult} authoritativeRun={authoritativeRun} />
              {isAuthoritativeCampaign && authoritativeRun ? <CampaignReplayScrubber run={authoritativeRun} value={campaignPlaybackMs} onChange={(value) => { setCampaignPlaybackMs(value); setCampaignRuntimePhase("paused"); }} /> : null}
            </section>
          ) : null}
          {activePanel === "settings" ? (
            <section className="drawer-section">
              {selectedBattery ? (
                <SelectedUnitPanel
                  selectedBattery={selectedBattery}
                  selectedUnit={selectedUnit}
                  onMaintain={startSelectedBatteryMaintenance}
                  onRecall={removeSelectedBattery}
                />
              ) : (
                <LiveStatusPanel placementKind={placementKind} placementWarning={game.placementWarning} />
              )}
              <button className="reset-button" type="button" onClick={() => setConfirmReset(true)}>
                <RotateCcw size={16} />
                {t("action.reset")}
              </button>
              <button className="reset-button reset-button--secondary" type="button" onClick={returnToCommandModes}>
                <Menu size={16} />
                Change Scenario
              </button>
              {tacticalMode !== "daily-defense" && tacticalMode !== "campaign" ? <button className="reset-button" type="button" disabled={!game.batteries.length || isResolving} onClick={() => { void resolveAuthoritativeOperation(); }}><Zap size={16} /> {isResolving ? "Resolving authoritative event stream…" : "Resolve operation on server"}</button> : null}
            </section>
          ) : null}
        </aside>
      ) : null}

      {!tutorialDismissed ? <TutorialOverlay onDismiss={dismissTutorial} /> : null}
      {confirmReset ? (
        <div className="confirm-overlay" role="dialog" aria-modal="true" aria-label="Reset campaign confirmation">
          <section className="confirm-card">
            <strong>Reset campaign?</strong>
            <span>This clears live threats, placements, and current resource state for this scenario.</span>
            <div>
              <button type="button" onClick={() => setConfirmReset(false)}>Cancel</button>
              <button
                type="button"
                onClick={() => {
                  handleResetOperation();
                  setConfirmReset(false);
                }}
              >
                Reset
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </main>
  );
}

function CampaignEventLog({ events }: { events: SimulationEvent[] }) {
  return (
    <section className="campaign-event-stream" aria-label="Authoritative campaign events">
      <div className="campaign-event-stream__heading">
        <span>{t("stream.title")}</span>
        <strong>{events.length ? t("stream.sequence", { sequence: formatNumber(events.at(-1)?.sequence || 0) }) : t("stream.waiting")}</strong>
      </div>
      <ol>
        {events.slice(-24).reverse().map((event) => (
          <li key={event.id} className={`campaign-event campaign-event--${event.type.replace(".", "-")}`}>
            <time>{formatNumber(Math.round(event.occurredAtMs / 1000))}с</time>
            <div><strong>{event.type.replace(".", " ")}</strong><span>{formatSimulationEvent(event)}</span></div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function CampaignReplayScrubber({ run, value, onChange }: { run: MissionRun; value: number; onChange: (value: number) => void }) {
  const end = run.events.at(-1)?.occurredAtMs || 0;
  const current = [...run.events].reverse().find((event) => event.occurredAtMs <= value);
  return (
    <section className="campaign-replay-controls" aria-label="Campaign tactical replay">
      <div>
        <span>{t("replay.title")}</span>
        <strong>{formatNumber(Math.round(value / 1000))}с / {formatNumber(Math.round(end / 1000))}с</strong>
      </div>
      <input type="range" min="0" max={end} step="100" value={Math.min(value, end)} onChange={(event) => onChange(Number(event.target.value))} aria-label="Campaign replay timeline" />
      <p>{current ? formatSimulationEvent(current) : t("replay.hint")}</p>
      <button type="button" className="reset-button reset-button--secondary" onClick={() => onChange(0)}><RotateCcw size={15} /> {t("replay.restart")}</button>
    </section>
  );
}

function LiveStatusPanel({ placementKind, placementWarning }: { placementKind: UnitKind | null; placementWarning: string | null }) {
  return (
    <section className="live-card" aria-label="Live simulation status">
      <Zap size={22} />
      <div>
        <strong>{placementKind ? "Click an allowed area to place unit" : "Live Defense Active"}</strong>
        <span>{placementWarning || "Targets stay hidden until radar scan reveals them."}</span>
      </div>
    </section>
  );
}

function CampaignStatusCard({ status, statusReason }: { status: CampaignStatus; statusReason: string }) {
  return (
    <div className={`status-card status-card--${status}`}>
      <Activity size={22} />
      <div>
        <strong>{status === "won" ? "Campaign Stabilized" : "Campaign Failed"}</strong>
        <span>{statusReason}</span>
      </div>
    </div>
  );
}

function AmmoLowCard() {
  return (
    <div className="status-card status-card--lost">
      <AlertTriangle size={20} />
      <div>
        <strong>Ammo Low</strong>
        <span>Coverage remains active, but engagements are limited.</span>
      </div>
    </div>
  );
}

function SelectedUnitPanel({
  selectedBattery,
  selectedUnit,
  onMaintain,
  onRecall,
}: {
  selectedBattery: DefenseBattery;
  selectedUnit: UnitDefinition | null;
  onMaintain: () => void;
  onRecall: () => void;
}) {
  return (
    <section className="selected-unit-card" aria-label="Selected defense unit">
      <div className="selected-unit-card__head">
        <Crosshair size={22} />
        <div>
          <strong>{selectedUnit?.name || "Selected PPO"}</strong>
          <span>{selectedBattery.status} · {selectedBattery.supplyStatus} · last: {selectedBattery.lastEngagementResult}</span>
        </div>
      </div>
      {selectedUnit ? (
        <>
          <div className="selected-unit-grid">
            <span><b>{selectedUnit.primaryRangeKm} km</b> primary</span>
            <span><b>{selectedUnit.outerRangeKm} km</b> outer</span>
            <span><b>{formatAmmo(selectedBattery.currentAmmo, selectedUnit.ammoCapacity)}</b> ammo</span>
            <span><b>{formatSeconds(selectedBattery.reloadRemainingMs)}</b> reload</span>
            <span><b>{formatSeconds(selectedBattery.cooldownMs)}</b> cooldown</span>
            <span><b>{Math.round(selectedBattery.readiness)}%</b> readiness</span>
            <span><b>{Math.round(selectedBattery.fatigue)}%</b> fatigue</span>
            <span><b>{selectedUnit.primaryAccuracy}%</b> primary acc</span>
            <span><b>{selectedUnit.outerAccuracy}%</b> outer acc</span>
          </div>
          <div className="chance-grid" aria-label="Threat-specific hit chances">
            {threatLabels.map(({ kind, label }) => (
              <span key={kind}>
                <b>{Math.round(selectedUnit.engagementChanceByThreat[kind])}%</b>
                {label}
              </span>
            ))}
          </div>
        </>
      ) : null}
      <div className="selected-unit-card__actions">
        <button type="button" onClick={onMaintain} disabled={selectedBattery.status === "maintenance" || selectedBattery.status === "reloading"}>Maintain</button>
        <button type="button" onClick={onRecall}>Recall</button>
      </div>
    </section>
  );
}
