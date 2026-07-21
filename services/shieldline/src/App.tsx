import { useCallback, useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, BookOpen, ChartNoAxesCombined, ClipboardList, Crosshair, HelpCircle, ListChecks, LogOut, Map as MapIcon, Menu, Radio, RadioTower, RotateCcw, Settings2, Shield, X, Zap } from "lucide-react";
import { AfterActionReport } from "./components/AfterActionReport";
import { AccountSettings } from "./components/AccountSettings";
import { AdminApp } from "./components/AdminApp";
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
import { DisplaySettings } from "./components/DisplaySettings";
import { BrandMark } from "./components/BrandMark";
import { apiGameRepository } from "./data/apiGameRepository";
import { getCampaignModeDefinition } from "./data/campaignModes";
import { defenseReadinessForMode, getGameModeRuntimePolicy } from "./data/gameModes";
import { campaignMissions } from "./data/missions";
import { activeCampaignTutorialCue, getCampaignMission } from "./data/campaignPlan";
import { getScenario } from "./data/scenarios";
import { getUnitDefinition } from "./data/units";
import { BATTLE_NOTICE_DURATION_MS, preferBattleNotice, selectBattleNotice } from "./game/battleNotices";
import { useGameStore } from "./store/useGameStore";
import { bindTelegramBackButton } from "./platform/telegramShell";
import { formatNumber, t } from "./platform/i18n";
import { trackAnalytics } from "./platform/analytics";
import { readDisplayPreferences, writeDisplayPreferences } from "./platform/displayPreferences";
import { readAudioPreferences, writeAudioPreferences } from "./platform/audioPreferences";
import { useGameAudio } from "./audio/useGameAudio";
import type { CampaignStatus, DefenseBattery, IntelEntry, MapMode, UnitKind } from "./types/game";
import type { DailyDefensePlan, GameModeId, MissionRun, RankedResult } from "./domain/contracts";

const mapModes: Array<{ id: MapMode; label: string }> = [
  { id: "live", label: "Бій" },
  { id: "threats", label: "Загрози" },
  { id: "coverage", label: "Покриття" },
  { id: "logistics", label: "Логістика" },
];

const SIMULATION_TICK_MS = 300;
const MAX_SIMULATION_FRAME_DELTA_MS = 1_000;
const RADAR_KINDS = new Set<UnitKind>(["small-radar", "radar", "long-radar"]);
function coOpSectorForCity(cityId: string) {
  if (["chernihiv", "sumy", "kyiv", "zhytomyr", "rivne", "lutsk"].includes(cityId)) return "north";
  if (["kharkiv", "dnipro", "zaporizhzhia", "poltava", "kryvyi-rih"].includes(cityId)) return "east";
  if (["odesa", "mykolaiv", "kropyvnytskyi", "cherkasy"].includes(cityId)) return "south";
  return "west";
}

function defensePlanFromBatteries(batteries: DefenseBattery[]): DailyDefensePlan {
  const assets = batteries.map((battery) => ({ id: battery.id, kind: battery.kind, cityId: battery.assignedCityId, readiness: battery.readiness, position: battery.position }));
  return { assetCount: assets.length, radarCount: assets.filter((asset) => RADAR_KINDS.has(asset.kind)).length, kineticCount: assets.filter((asset) => !RADAR_KINDS.has(asset.kind) && asset.kind !== "ew").length, averageReadiness: assets.length ? assets.reduce((sum, asset) => sum + asset.readiness, 0) / assets.length : 0, assets };
}

type ActivePanel = "menu" | "layers" | "units" | "planning" | "intel" | "report" | "settings";

const desktopPanelItems: Array<{ id: ActivePanel; label: string; icon: typeof MapIcon }> = [
  { id: "layers", label: t("panel.layers"), icon: MapIcon },
  { id: "units", label: t("panel.units"), icon: Shield },
  { id: "planning", label: t("panel.planning"), icon: ListChecks },
  { id: "intel", label: t("panel.intel"), icon: RadioTower },
  { id: "report", label: t("panel.report"), icon: ChartNoAxesCombined },
  { id: "settings", label: t("panel.settings"), icon: Settings2 },
];

const mobilePanelItems: Array<{ id: ActivePanel; label: string; icon: typeof MapIcon }> = [
  { id: "menu", label: "Меню", icon: Menu },
  { id: "units", label: "ППО", icon: Shield },
  { id: "planning", label: "План", icon: ListChecks },
  { id: "intel", label: "Розвідка", icon: RadioTower },
  { id: "settings", label: "Налаштування", icon: Settings2 },
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
    return <AdminApp />;
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
  const advanceCampaignMission = useGameStore((state) => state.advanceCampaignMission);
  const advanceOperation = useGameStore((state) => state.advanceOperation);
  const placementKind = useGameStore((state) => state.placementKind);
  const cancelPlacement = useGameStore((state) => state.cancelPlacement);
  const activeGameMode = useGameStore((state) => state.activeGameMode);
  const operationPhase = useGameStore((state) => state.operationPhase);
  const simulationSeed = useGameStore((state) => state.simulationSeed);
  const tacticalMode = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("mode") : null;
  const isMobileViewport = useMobileViewport();
  const isMobileLive = isMobileViewport;
  const [confirmReset, setConfirmReset] = useState(false);
  const [activePanel, setActivePanel] = useState<ActivePanel | null>(() => isMobileLive ? null : "units");
  const [battleNotice, setBattleNotice] = useState<IntelEntry | null>(null);
  const [rankedResult, setRankedResult] = useState<RankedResult | null>(null);
  const [authoritativeRun, setAuthoritativeRun] = useState<MissionRun | null>(null);
  const [isResolving, setIsResolving] = useState(false);
  const [displayPreferences, setDisplayPreferences] = useState(readDisplayPreferences);
  const [audioPreferences, setAudioPreferences] = useState(readAudioPreferences);
  const [fullscreenReportOpen, setFullscreenReportOpen] = useState(false);
  const [visitedCampaignPanels, setVisitedCampaignPanels] = useState<ActivePanel[]>([]);
  const coOpSyncedBatteryIds = useRef(new Set<string>());
  const campaignSyncedBatteryIds = useRef(new Set<string>());
  const dailySavedPlanRef = useRef<string | null>(null);
  const completedCampaignReportRef = useRef<string | null>(null);
  const latestBattleNoticeIdRef = useRef<string | null>(null);
  const latestReportIdRef = useRef<string | null>(null);
  const modeDefinition = campaignMode ? getCampaignModeDefinition(campaignMode) : null;
  const scenario = getScenario(game.scenarioId);
  const lastTickRef = useRef<number | null>(null);
  const accumulatorRef = useRef(0);
  const revealedThreats = game.liveThreats.filter((threat) => threat.revealed).length;
  const resolvedMode = (activeGameMode || tacticalMode || "training") as GameModeId;
  const runtimePolicy = getGameModeRuntimePolicy(resolvedMode);
  const coOpSession = (() => {
    if (typeof window === "undefined" || tacticalMode !== "co-op-command") return null;
    try { return JSON.parse(window.sessionStorage.getItem("shieldline-coop-session") || "null") as { roomId: string; sectorId: string } | null; } catch { return null; }
  })();
  const activeMission = campaignMissions[(game.campaign?.missionIndex || 1) - 1] || campaignMissions[0];
  const activeMissionTitle = game.campaign ? getCampaignMission(game.campaign.missionIndex).title : t("mission.1");
  const missionElapsedSeconds = Math.max(0, (game.elapsedMs - game.cycleStartedAtMs) / 1_000);
  const campaignTutorial = game.campaign?.missionIndex === 1 && operationPhase === "running"
    ? activeCampaignTutorialCue(missionElapsedSeconds, visitedCampaignPanels)
    : null;
  const returnToCommandModes = () => {
    const url = new URL(window.location.href);
    url.search = "";
    window.location.assign(url.toString());
  };
  const inspectCompletedMap = useCallback(() => {
    setFullscreenReportOpen(false);
    setActivePanel(null);
  }, []);
  const continueCampaignMission = useCallback(() => {
    advanceCampaignMission();
    setFullscreenReportOpen(false);
    setActivePanel(isMobileLive ? null : "units");
  }, [advanceCampaignMission, isMobileLive]);
  const handleResetOperation = () => {
    if (tacticalMode === "campaign") window.localStorage.removeItem("shieldline-campaign-operation-v1");
    resetCampaign();
  };

  useEffect(() => bindTelegramBackButton(returnToCommandModes), []);

  useEffect(() => {
    writeDisplayPreferences(displayPreferences);
  }, [displayPreferences]);

  useEffect(() => {
    writeAudioPreferences(audioPreferences);
  }, [audioPreferences]);

  useGameAudio({ game, operationPhase, simulationSeed, preferences: audioPreferences });

  useEffect(() => {
    const battleEntries = game.log.filter((entry) => entry.eventType === "launch" || entry.eventType === "detection");
    const previousLatestIndex = latestBattleNoticeIdRef.current
      ? battleEntries.findIndex((entry) => entry.id === latestBattleNoticeIdRef.current)
      : -1;
    const unseenEntries = previousLatestIndex >= 0 ? battleEntries.slice(0, previousLatestIndex) : battleEntries;
    latestBattleNoticeIdRef.current = battleEntries[0]?.id || null;
    const incoming = selectBattleNotice(unseenEntries);
    if (!incoming) return;
    setBattleNotice((current) => preferBattleNotice(current, incoming));
  }, [game.log]);

  useEffect(() => {
    if (!battleNotice) return undefined;
    const timeout = window.setTimeout(() => setBattleNotice(null), BATTLE_NOTICE_DURATION_MS);
    return () => window.clearTimeout(timeout);
  }, [battleNotice]);

  useEffect(() => {
    if (operationPhase !== "completed" || !game.latestReportId || game.latestReportId === latestReportIdRef.current) return;
    latestReportIdRef.current = game.latestReportId;
    setFullscreenReportOpen(true);
  }, [game.latestReportId, operationPhase]);

  useEffect(() => {
    if (isMobileLive && activePanel === "layers") setActivePanel("menu");
  }, [activePanel, isMobileLive]);

  useEffect(() => {
    if (!campaignMode || runtimePolicy.execution !== "live" || (operationPhase !== "running" && operationPhase !== "countdown")) return undefined;
    let frameId = 0;
    let active = true;
    const resetSimulationClock = () => {
      lastTickRef.current = null;
      accumulatorRef.current = 0;
    };
    const frame = (timestamp: number) => {
      try {
        if (document.hidden) {
          resetSimulationClock();
          return;
        }
        if (lastTickRef.current === null) {
          lastTickRef.current = timestamp;
          return;
        }
        const delta = Math.min(Math.max(0, timestamp - lastTickRef.current), MAX_SIMULATION_FRAME_DELTA_MS);
        lastTickRef.current = timestamp;
        accumulatorRef.current += delta;
        if (accumulatorRef.current >= SIMULATION_TICK_MS) {
          advanceOperation(accumulatorRef.current);
          accumulatorRef.current = 0;
        }
      } catch (error) {
        console.error("Shieldline animation frame recovered", error);
        resetSimulationClock();
      } finally {
        if (active) frameId = window.requestAnimationFrame(frame);
      }
    };
    const handleVisibilityChange = () => resetSimulationClock();
    const handlePageLifecycle = () => resetSimulationClock();
    document.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("pagehide", handlePageLifecycle);
    window.addEventListener("pageshow", handlePageLifecycle);
    frameId = window.requestAnimationFrame(frame);
    return () => {
      active = false;
      window.cancelAnimationFrame(frameId);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      window.removeEventListener("pagehide", handlePageLifecycle);
      window.removeEventListener("pageshow", handlePageLifecycle);
      resetSimulationClock();
    };
  }, [advanceOperation, campaignMode, operationPhase, runtimePolicy.execution]);

  useEffect(() => {
    lastTickRef.current = null;
    accumulatorRef.current = 0;
  }, [resolvedMode, operationPhase]);

  useEffect(() => {
    if (tacticalMode !== "campaign" || operationPhase !== "completed" || !game.latestReportId) return;
    setFullscreenReportOpen(true);
    if (completedCampaignReportRef.current === game.latestReportId) return;
    completedCampaignReportRef.current = game.latestReportId;
    trackAnalytics("campaign.operation.completed", { reportId: game.latestReportId, interceptions: game.interceptions, impacts: game.impacts });
  }, [game.impacts, game.interceptions, game.latestReportId, operationPhase, tacticalMode]);

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
      setFullscreenReportOpen(true);
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

  const panelItems = isMobileLive
    ? game.campaign?.intermission && !game.campaign.completed
      ? [mobilePanelItems[0], mobilePanelItems[1], { id: "report" as const, label: "Звіт", icon: ClipboardList }, mobilePanelItems[3], mobilePanelItems[4]]
      : mobilePanelItems
    : desktopPanelItems;
  const placementUnit = placementKind ? getUnitDefinition(placementKind) : null;
  const defenseReadiness = defenseReadinessForMode(resolvedMode, game.batteries.map((battery) => battery.kind));
  const ownedBatteryKinds = [...game.batteries, ...(game.storedBatteries || [])].map((battery) => battery.kind);
  const hasOwnedRadar = ownedBatteryKinds.includes("radar");
  const hasOwnedKinetic = ownedBatteryKinds.some((kind) => !RADAR_KINDS.has(kind) && kind !== "ew");
  const setupGuidance = operationPhase === "planning" && runtimePolicy.start === "auto-checklist" && !defenseReadiness.ready
    ? !hasOwnedRadar
      ? { kind: "radar" as const, text: "Спочатку встановіть радар" }
      : !hasOwnedKinetic
        ? { kind: "kinetic" as const, text: "Тепер встановіть бойову ППО" }
        : null
    : null;
  const activePanelTitle = activePanel
    ? isMobileLive
      ? panelTitle[activePanel]
      : desktopPanelItems.find((item) => item.id === activePanel)?.label || panelTitle[activePanel]
    : "";

  return (
    <main className={`shell shell--map-first environment--${displayPreferences.environmentTime} weather--${displayPreferences.environmentWeather} ${displayPreferences.performanceMode ? "shell--performance-mode" : ""} ${isMobileLive ? "shell--mobile-live" : ""} ${activePanel ? "shell--drawer-open shell--panel-open" : "shell--drawer-closed"}`} data-audio-scope="player" aria-label="Симуляція протиповітряної оборони Shieldline">
      <nav className="app-rail" aria-label="Панелі Shieldline">
        {!isMobileLive ? <button className="rail-button rail-button--menu" type="button" aria-label="До вибору режиму" onClick={returnToCommandModes}>
          <span className="rail-icon"><Menu size={21} strokeWidth={2.2} /></span>
        </button> : null}
        <div className="rail-brand" aria-hidden="true">
          <BrandMark size={26} />
        </div>
        <div className="rail-button-stack">
          {panelItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                className={`rail-button ${activePanel === item.id ? "rail-button--active" : ""} ${campaignTutorial && "panelTarget" in campaignTutorial && campaignTutorial.panelTarget === item.id ? "rail-button--tutorial-target" : ""}`}
                type="button"
                key={item.id}
                data-testid={`panel-${item.id}`}
                onClick={() => {
                  if (!visitedCampaignPanels.includes(item.id)) setVisitedCampaignPanels((current) => [...current, item.id]);
                  setActivePanel((current) => (current === item.id ? null : item.id));
                }}
                aria-label={item.label}
                aria-pressed={activePanel === item.id}
                title={item.label}
              >
                <span className="rail-icon"><Icon size={20} strokeWidth={2.15} /></span>
                <span className="rail-label">{item.label}</span>
              </button>
            );
          })}
        </div>
      </nav>

      <section className={`map-stage map-stage--${mapMode} ${placementKind ? "map-stage--placing" : ""}`} aria-label="Мапа протиповітряної оборони" aria-hidden={fullscreenReportOpen || (isMobileLive && Boolean(activePanel))}>
        <TacticalMap forcedReducedQuality={displayPreferences.performanceMode} />
        <div className="environment-overlay" aria-hidden="true"><i /><b /></div>
        <header className="map-status-strip" aria-label="Стан операції">
          <div className="strip-brand">
            <BrandMark size={24} />
            <div>
              <h1>Shieldline</h1>
              <span>{tacticalMode === "campaign" ? `${activeMissionTitle} · жива операція` : `${scenario.title} · ${modeDefinition?.title || "Живий захист"} · ${t(`operation.${operationPhase}`)}`}</span>
            </div>
          </div>
          <ResourceBar game={game} operationPhase={operationPhase} mobile={isMobileLive} />
        </header>
        <MapLegend mode={mapMode} game={game} />
      </section>

      {battleNotice || placementUnit || setupGuidance || campaignTutorial ? (
        <div
          className={`map-feedback-slot ${battleNotice ? `map-feedback-slot--${battleNotice.eventType}` : placementUnit ? "map-feedback-slot--placement" : "map-feedback-slot--guidance"}`}
          role="status"
          aria-live={battleNotice ? "assertive" : "polite"}
        >
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
          ) : setupGuidance ? (
            <>
              {setupGuidance.kind === "radar" ? <Radio size={17} /> : <Shield size={17} />}
              <strong>{setupGuidance.text}</strong>
            </>
          ) : campaignTutorial ? <><BookOpen size={17} /><div><strong>{campaignTutorial.title}</strong><span>{campaignTutorial.body}</span></div></> : null}
        </div>
      ) : null}

      {activePanel ? (
        <aside className={`command-drawer command-drawer--${activePanel}`} aria-label={`Панель «${activePanelTitle}»`}>
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
                <MapLegend mode={mapMode} game={game} embedded />
              </section>
              <section className="menu-group menu-help">
                <HelpCircle size={21} />
                <div><strong>Як керувати</strong><span>Масштабуйте мапу двома пальцями. Виберіть ППО з каталогу, поверніться на мапу й торкніться дозволеної ділянки.</span></div>
              </section>
              {game.campaign?.intermission && !game.campaign.completed ? <section className="campaign-next-mission-card"><span>Наступна операція відкрита</span><strong>Місія {game.campaign.missionIndex + 1}</strong><button type="button" onClick={continueCampaignMission}>Перейти до місії {game.campaign.missionIndex + 1}</button></section> : null}
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
              <div className="live-stats live-stats--drawer" aria-label="Телеметрія протиповітряної оборони">
                <span><strong>{formatNumber(game.day)}</strong> {t("stats.cycle")}</span>
                <span><strong>{formatNumber(revealedThreats)}</strong> {t("stats.revealed")}</span>
                <span><strong>{formatNumber(game.interceptions)}</strong> {t("stats.interceptions")}</span>
                <span><strong>{formatNumber(game.impacts)}</strong> {t("stats.impacts")}</span>
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
              <IntelLog game={game} />
              {game.status !== "active" ? <CampaignStatusCard status={game.status} statusReason={game.statusReason} /> : null}
            </section>
          ) : null}
          {activePanel === "report" ? (
            <section className="drawer-section">
              <AfterActionReport game={game} rankedResult={rankedResult} authoritativeRun={tacticalMode === "campaign" ? null : authoritativeRun} onContinueCampaign={continueCampaignMission} />
            </section>
          ) : null}
          {activePanel === "settings" ? (
            <section className="drawer-section">
              <AccountSettings />
              <DisplaySettings preferences={displayPreferences} onChange={setDisplayPreferences} audioPreferences={audioPreferences} onAudioChange={setAudioPreferences} />
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

      {fullscreenReportOpen ? (
        <div className="aar-fullscreen" role="dialog" aria-modal="true" aria-label="Післяопераційний звіт">
          <AfterActionReport
            game={game}
            rankedResult={rankedResult}
            authoritativeRun={tacticalMode === "campaign" ? null : authoritativeRun}
            variant="fullscreen"
            onInspectMap={inspectCompletedMap}
            onExit={returnToCommandModes}
            onContinueCampaign={continueCampaignMission}
          />
        </div>
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
