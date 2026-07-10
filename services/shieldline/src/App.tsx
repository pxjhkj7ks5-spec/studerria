import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, AlertTriangle, BookOpen, ClipboardList, Crosshair, HelpCircle, Layers, LogOut, Menu, Radio, RotateCcw, Settings, Shield, SlidersHorizontal, X, Zap } from "lucide-react";
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
import { BATTLE_NOTICE_DURATION_MS, preferBattleNotice } from "./game/battleNotices";
import { useGameStore } from "./store/useGameStore";
import { bindTelegramBackButton, bindTelegramBottomButton } from "./platform/telegramShell";
import { formatNumber, formatSimulationEvent, t } from "./platform/i18n";
import { trackAnalytics } from "./platform/analytics";
import type { CampaignStatus, DefenseBattery, IntelEntry, MapMode, UnitKind } from "./types/game";
import type { CampaignProgress, DailyDefensePlan, GameModeId, MissionRun, OperationPhase, RankedResult, SimulationEvent } from "./domain/contracts";

const mapModes: Array<{ id: MapMode; label: string }> = [
  { id: "live", label: "Бій" },
  { id: "threats", label: "Загрози" },
  { id: "coverage", label: "Покриття" },
  { id: "logistics", label: "Логістика" },
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

type ActivePanel = "menu" | "layers" | "units" | "planning" | "intel" | "report" | "settings";

const desktopPanelItems: Array<{ id: ActivePanel; label: string; icon: typeof Layers }> = [
  { id: "layers", label: t("panel.layers"), icon: Layers },
  { id: "units", label: t("panel.units"), icon: Crosshair },
  { id: "planning", label: t("panel.planning"), icon: SlidersHorizontal },
  { id: "intel", label: t("panel.intel"), icon: Radio },
  { id: "report", label: t("panel.report"), icon: ClipboardList },
  { id: "settings", label: t("panel.settings"), icon: Settings },
];

const mobilePanelItems: Array<{ id: ActivePanel; label: string; icon: typeof Layers }> = [
  { id: "menu", label: "Меню", icon: Menu },
  { id: "units", label: "ППО", icon: Crosshair },
  { id: "planning", label: "План", icon: SlidersHorizontal },
  { id: "intel", label: "Розвідка", icon: Radio },
  { id: "settings", label: "Налаштування", icon: Settings },
];

const panelTitle: Record<ActivePanel, string> = {
  menu: "Меню",
  layers: "Шари",
  units: "ППО",
  planning: "План",
  intel: "Розвідка",
  report: "Післяопераційний звіт",
  settings: "Налаштування",
};

const cityLabelsUk: Record<string, string> = {
  kyiv: "Київ",
  lviv: "Львів",
  odesa: "Одеса",
  dnipro: "Дніпро",
  kharkiv: "Харків",
  zaporizhzhia: "Запоріжжя",
  mykolaiv: "Миколаїв",
  chernihiv: "Чернігів",
  sumy: "Суми",
  poltava: "Полтава",
  cherkasy: "Черкаси",
  kropyvnytskyi: "Кропивницький",
  "kryvyi-rih": "Кривий Ріг",
  zhytomyr: "Житомир",
  vinnytsia: "Вінниця",
  khmelnytskyi: "Хмельницький",
  ternopil: "Тернопіль",
  rivne: "Рівне",
  lutsk: "Луцьк",
  "ivano-frankivsk": "Івано-Франківськ",
  uzhhorod: "Ужгород",
  chernivtsi: "Чернівці",
};

function useMobileViewport() {
  const queryText = "(max-width: 820px), (max-width: 920px) and (max-height: 520px)";
  const [mobile, setMobile] = useState(() => typeof window !== "undefined" && window.matchMedia(queryText).matches);
  useEffect(() => {
    const query = window.matchMedia(queryText);
    const update = () => setMobile(query.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, [queryText]);
  return mobile;
}

function noticeCopy(entry: IntelEntry) {
  const location = cityLabelsUk[entry.locationLabel || ""] || entry.locationLabel || "невідомий напрямок";
  return entry.eventType === "launch" ? `Пуски: ${location}` : `Ціль виявлено: напрямок на ${location}`;
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
  const placementKind = useGameStore((state) => state.placementKind);
  const cancelPlacement = useGameStore((state) => state.cancelPlacement);
  const activeGameMode = useGameStore((state) => state.activeGameMode);
  const operationPhase = useGameStore((state) => state.operationPhase);
  const simulationSpeed = useGameStore((state) => state.simulationSpeed);
  const tacticalMode = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("mode") : null;
  const isMobileViewport = useMobileViewport();
  const isMobileLive = isMobileViewport && tacticalMode !== "campaign";
  const [confirmReset, setConfirmReset] = useState(false);
  const [activePanel, setActivePanel] = useState<ActivePanel | null>(() => isMobileLive ? null : "units");
  const [battleNotice, setBattleNotice] = useState<IntelEntry | null>(null);
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
  const latestNoticeIdRef = useRef<string | null>(null);
  const latestReportIdRef = useRef(game.latestReportId);
  const modeDefinition = campaignMode ? getCampaignModeDefinition(campaignMode) : null;
  const scenario = getScenario(game.scenarioId);
  const lastTickRef = useRef<number | null>(null);
  const accumulatorRef = useRef(0);
  const revealedThreats = game.liveThreats.filter((threat) => threat.revealed).length;
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
    visible: !isAuthoritativeCampaign && runtimePolicy.execution === "live" && runtimePolicy.start !== "auto-checklist" && effectiveOperationPhase === "planning",
    onClick: handleStartOperation,
  }), [defenseReadiness.ready, effectiveOperationPhase, runtimePolicy.execution, runtimePolicy.start, isAuthoritativeCampaign, isResolving, game.batteries, activeMission.id]);

  useEffect(() => {
    if (!isMobileLive) return;
    const latest = game.log.find((entry) => entry.eventType === "launch" || entry.eventType === "detection");
    if (!latest || latest.id === latestNoticeIdRef.current) return;
    latestNoticeIdRef.current = latest.id;
    setBattleNotice((current) => preferBattleNotice(current, latest));
  }, [game.log, isMobileLive]);

  useEffect(() => {
    if (!battleNotice) return undefined;
    const timeout = window.setTimeout(() => setBattleNotice(null), BATTLE_NOTICE_DURATION_MS);
    return () => window.clearTimeout(timeout);
  }, [battleNotice]);

  useEffect(() => {
    if (!isMobileLive || !game.latestReportId || game.latestReportId === latestReportIdRef.current) return;
    latestReportIdRef.current = game.latestReportId;
    setActivePanel("report");
  }, [game.latestReportId, isMobileLive]);

  useEffect(() => {
    if (isMobileLive && activePanel === "layers") setActivePanel("menu");
  }, [activePanel, isMobileLive]);

  useEffect(() => {
    if (!isAuthoritativeCampaign || campaignRuntimePhase !== "planning" || !defenseReadiness.ready || isResolving) return;
    void startCampaignOperation();
  }, [activeMission.id, campaignRuntimePhase, defenseReadiness.ready, isAuthoritativeCampaign, isResolving]);

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

  const panelItems = isMobileLive ? mobilePanelItems : desktopPanelItems;
  const placementUnit = placementKind ? getUnitDefinition(placementKind) : null;
  const activePanelTitle = activePanel
    ? isMobileLive
      ? panelTitle[activePanel]
      : desktopPanelItems.find((item) => item.id === activePanel)?.label || panelTitle[activePanel]
    : "";

  return (
    <main className={`shell shell--map-first ${isMobileLive ? "shell--mobile-live" : ""} ${activePanel ? "shell--drawer-open shell--panel-open" : "shell--drawer-closed"}`} aria-label="Симуляція протиповітряної оборони Shieldline">
      <nav className="app-rail" aria-label={isMobileLive ? "Панелі Shieldline" : "Shieldline panels"}>
        {!isMobileLive ? <button className="rail-button rail-button--menu" type="button" aria-label="До вибору режиму" onClick={returnToCommandModes}>
          <Menu size={24} />
        </button> : null}
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
                data-testid={`panel-${item.id}`}
                onClick={() => {
                  if (item.id === "report" && authoritativeRun) trackAnalytics("campaign.replay.opened", { runId: authoritativeRun.id, source: "navigation" });
                  setActivePanel((current) => (current === item.id ? null : item.id));
                }}
                aria-label={item.label}
                aria-pressed={activePanel === item.id}
                title={item.label}
              >
                <Icon size={21} />
                <span className="rail-label">{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      <section className={`map-stage map-stage--${mapMode} ${placementKind ? "map-stage--placing" : ""}`} aria-label="Мапа протиповітряної оборони" aria-hidden={isMobileLive && Boolean(activePanel)}>
        <TacticalMap projection={campaignProjection} />
        <header className="map-status-strip" aria-label="Стан операції">
          <div className="strip-brand">
            <Shield size={22} />
            <div>
              <h1>Shieldline</h1>
              <span>{tacticalMode === "campaign" ? `${activeMissionTitle} · ${t("stream.title")}` : `${scenario.title} · ${modeDefinition?.title || "Live defense"} · ${game.cyclePhase}`}</span>
            </div>
          </div>
          <ResourceBar game={displayGame} simulationSpeed={simulationSpeed} operationPhase={effectiveOperationPhase} mobile={isMobileLive} />
        </header>
        {isMobileLive && (battleNotice || placementUnit) ? (
          <div className={`map-feedback-slot ${battleNotice ? `map-feedback-slot--${battleNotice.eventType}` : "map-feedback-slot--placement"}`} role="status" aria-live="assertive">
            {battleNotice ? (
              <>
                {battleNotice.eventType === "launch" ? <AlertTriangle size={17} /> : <Radio size={17} />}
                <strong>{noticeCopy(battleNotice)}</strong>
              </>
            ) : placementUnit ? (
              <>
                <Crosshair size={17} />
                <div><strong>Розмістіть: {placementUnit.shortName}</strong>{game.placementWarning ? <span>{game.placementWarning}</span> : null}</div>
                <button type="button" onClick={cancelPlacement}>Скасувати</button>
              </>
            ) : null}
          </div>
        ) : null}
        <MapLegend mode={mapMode} />
      </section>

      {activePanel ? (
        <aside className={`command-drawer command-drawer--${activePanel}`} aria-label={isMobileLive ? `Панель «${activePanelTitle}»` : `${activePanelTitle} panel`}>
          <div className="drawer-header">
            <div>
              <span>Shieldline</span>
              <strong>{activePanelTitle}</strong>
            </div>
            <button className="drawer-close" type="button" aria-label="Закрити" onClick={() => setActivePanel(null)}>
              <X size={18} />
            </button>
          </div>
          {activePanel === "menu" ? (
            <section className="drawer-section mobile-menu-panel">
              <div className="mobile-menu-intro">
                <BookOpen size={24} />
                <div><strong>Командний центр</strong><span>Оберіть шар мапи, перегляньте позначення або поверніться до режимів.</span></div>
              </div>
              <section className="menu-group" aria-labelledby="mobile-layer-heading">
                <h2 id="mobile-layer-heading">Шар мапи</h2>
                <div className="panel-layer-list">
                  {mapModes.map((mode) => (
                    <button className={`nav-pill ${mapMode === mode.id ? "nav-pill--active" : ""}`} type="button" key={mode.id} onClick={() => setMapMode(mode.id)}>{mode.label}</button>
                  ))}
                </div>
              </section>
              <section className="menu-group">
                <MapLegend mode={mapMode} embedded />
              </section>
              <section className="menu-group menu-help">
                <HelpCircle size={21} />
                <div><strong>Як керувати</strong><span>Масштабуйте мапу двома пальцями. Виберіть ППО з каталогу, поверніться на мапу й торкніться дозволеної ділянки.</span></div>
              </section>
              <button className="reset-button reset-button--secondary menu-exit-button" type="button" onClick={returnToCommandModes}><LogOut size={17} /> До вибору режиму</button>
            </section>
          ) : null}
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
              <LiveStatusPanel placementKind={placementKind} placementWarning={game.placementWarning} />
            </section>
          ) : null}
          {activePanel === "units" ? <UnitRail onPlacementStart={() => { if (isMobileLive) setActivePanel(null); }} /> : null}
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
              <LiveStatusPanel placementKind={placementKind} placementWarning={game.placementWarning} />
              <button className="reset-button" type="button" onClick={() => setConfirmReset(true)}>
                <RotateCcw size={16} />
                Скинути операцію
              </button>
              <button className="reset-button reset-button--secondary" type="button" onClick={returnToCommandModes}>
                <Menu size={16} />
                До вибору режиму
              </button>
              {tacticalMode !== "daily-defense" && tacticalMode !== "campaign" ? <button className="reset-button" type="button" disabled={!game.batteries.length || isResolving} onClick={() => { void resolveAuthoritativeOperation(); }}><Zap size={16} /> {isResolving ? "Опрацьовуємо події…" : "Завершити операцію"}</button> : null}
            </section>
          ) : null}
        </aside>
      ) : null}

      {!tutorialDismissed ? <TutorialOverlay onDismiss={dismissTutorial} /> : null}
      {confirmReset ? (
        <div className="confirm-overlay" role="dialog" aria-modal="true" aria-label="Підтвердження скидання операції">
          <section className="confirm-card">
            <strong>Скинути операцію?</strong>
            <span>Буде очищено поточні загрози, розміщені установки та ресурси цього сценарію.</span>
            <div>
              <button type="button" onClick={() => setConfirmReset(false)}>Скасувати</button>
              <button
                type="button"
                onClick={() => {
                  handleResetOperation();
                  setConfirmReset(false);
                }}
              >
                Скинути
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
    <section className="live-card" aria-label="Стан симуляції">
      <Zap size={22} />
      <div>
        <strong>{placementKind ? "Торкніться дозволеної ділянки на мапі" : "Живий режим активний"}</strong>
        <span>{placementWarning || "Цілі залишаються прихованими, доки їх не виявить радар."}</span>
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
        <strong>Мало боєкомплекту</strong>
        <span>Зона прикриття активна, але кількість перехоплень обмежена.</span>
      </div>
    </div>
  );
}
