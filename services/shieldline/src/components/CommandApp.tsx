import { useEffect, useState, type ReactNode } from "react";
import { Activity, ArrowLeft, BarChart3, Check, ChevronRight, CircleHelp, Clock3, Command, Crosshair, FileText, Flag, Gamepad2, Headphones, Home, Lock, Play, Radio, Shield, Swords, Trophy, UserRound, Users, Waves, Zap } from "lucide-react";
import { AccountSettings } from "./AccountSettings";
import { BrandMark } from "./BrandMark";
import { useAuth } from "./AuthGate";
import { apiGameRepository } from "../data/apiGameRepository";
import { gameModes, getGameMode } from "../data/gameModes";
import { campaignMissions } from "../data/missions";
import { setTelegramNotificationPreference, telegramCommandFeedback } from "../platform/telegramShell";
import { t } from "../platform/i18n";
import { trackAnalytics } from "../platform/analytics";
import { useGameStore } from "../store/useGameStore";
import { unlockedCampaignMissionIndex } from "../game/campaignMeta";
import type { CoOpRoom, DailyReport, GameModeId, LeaderboardEntry, MissionRun, SectorId } from "../domain/contracts";

type Screen = "modes" | "briefing" | "operation" | "report" | "daily" | "ranking" | "coop";
type Tab = "city" | "operations" | "squad" | "rating" | "reports";

const icons: Record<GameModeId, typeof Shield> = { campaign: Swords, "rapid-response": Zap, "daily-defense": Home, "ranked-challenge": Trophy, "co-op-command": Users, sandbox: Gamepad2, training: CircleHelp };
const sectorNames: Record<Exclude<SectorId, "hq">, string> = { north: "North", south: "South", east: "East", west: "West" };

export function CommandApp() {
  const [screen, setScreen] = useState<Screen>("modes");
  const [selectedMode, setSelectedMode] = useState<GameModeId>("campaign");
  const [selectedCampaignMission, setSelectedCampaignMission] = useState(1);
  const [run, setRun] = useState<MissionRun | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("operations");
  const [isRunning, setIsRunning] = useState(false);
  const [dailyReport, setDailyReport] = useState<DailyReport | null>(null);
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [room, setRoom] = useState<CoOpRoom | null>(null);
  const launchTacticalMode = useGameStore((state) => state.launchTacticalMode);
  const openCampaignMission = useGameStore((state) => state.openCampaignMission);
  const campaign = useGameStore((state) => state.game.campaign);
  const hydrateDailyCity = useGameStore((state) => state.hydrateDailyCity);
  const dailyCityGame = useGameStore((state) => state.dailyCityGame);
  const unlockedMissionIndex = unlockedCampaignMissionIndex(campaign);

  useEffect(() => {
    setSelectedCampaignMission(unlockedMissionIndex);
  }, [unlockedMissionIndex]);

  useEffect(() => { trackAnalytics("app.open", { surface: "campaign-catalog" }); }, []);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "auto" });
  }, [screen]);

  useEffect(() => {
    if (screen !== "coop") return undefined;
    const refresh = () => { void apiGameRepository.getCoOpRoom("kyiv-01").then(setRoom).catch(() => undefined); };
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => window.clearInterval(interval);
  }, [screen]);

  const selectMode = (id: GameModeId, missionIndex = 1) => {
    if (id === "co-op-command") {
      void apiGameRepository.getCoOpRoom("kyiv-01").then((nextRoom) => { setRoom(nextRoom); setScreen("coop"); });
      return;
    }
    if (id === "campaign") {
      setSelectedMode(id);
      setSelectedCampaignMission(missionIndex);
      setScreen("briefing");
      return;
    }
    if (id !== "daily-defense") {
      openManualCommand(id);
      return;
    }
    setSelectedMode(id);
    setScreen("briefing");
  };

  const openManualCommand = (mode: Exclude<GameModeId, "daily-defense">, missionIndex = 1) => {
    if (mode === "campaign") openCampaignMission(missionIndex);
    else launchTacticalMode(mode);
    const url = new URL(window.location.href);
    url.searchParams.set("legacy", "1");
    url.searchParams.set("mode", mode);
    window.location.assign(url.toString());
  };

  const runMission = async () => {
    setIsRunning(true);
    try {
      if (selectedMode === "daily-defense") {
        if (!dailyCityGame || dailyCityGame.batteries.length === 0) {
          const persistedCity = await apiGameRepository.getDailyCity().catch(() => null);
          if (persistedCity?.assets.length) hydrateDailyCity(persistedCity);
          launchTacticalMode("daily-defense");
          const url = new URL(window.location.href);
          url.searchParams.set("legacy", "1");
          url.searchParams.set("mode", "daily-defense");
          window.location.assign(url.toString());
          return;
        }
        const assets = dailyCityGame.batteries.map((battery) => ({ kind: battery.kind, cityId: battery.assignedCityId, readiness: battery.readiness }));
        const report = await apiGameRepository.getDailyReport(new Date().toISOString().slice(0, 10), {
          assetCount: assets.length,
          radarCount: assets.filter((asset) => ["small-radar", "radar", "long-radar"].includes(asset.kind)).length,
          kineticCount: assets.filter((asset) => !["small-radar", "radar", "long-radar", "ew"].includes(asset.kind)).length,
          averageReadiness: assets.reduce((sum, asset) => sum + asset.readiness, 0) / assets.length,
          assets,
        });
        const dailyRun = report ? await apiGameRepository.getRun(report.runId) : null;
        if (report && dailyRun) { setDailyReport(report); setRun(dailyRun); setScreen("daily"); telegramCommandFeedback(); }
        return;
      }
      openManualCommand(selectedMode, selectedCampaignMission);
    } finally { setIsRunning(false); }
  };

  if (screen === "modes") return <ModeCatalog onSelect={selectMode} campaign={campaign} unlockedMissionIndex={unlockedMissionIndex} />;
  if (screen === "briefing") return <Briefing modeId={selectedMode} missionIndex={selectedCampaignMission} onBack={() => setScreen("modes")} onStart={runMission} isRunning={isRunning} />;
  if (screen === "ranking") return <CommandFrame onBack={() => setScreen("modes")}><Ranking entries={leaderboard} /></CommandFrame>;
  if (screen === "coop") return <CommandFrame onBack={() => setScreen("modes")}><Coop room={room} onClaim={async (sectorId) => setRoom(await apiGameRepository.claimCoOpSector("kyiv-01", sectorId))} onEnter={(sectorId) => { window.sessionStorage.setItem("shieldline-coop-session", JSON.stringify({ roomId: "kyiv-01", sectorId })); openManualCommand("co-op-command"); }} /></CommandFrame>;
  if (screen === "daily") return <CommandFrame onBack={() => setScreen("modes")}><DailyDefense report={dailyReport} run={run} /></CommandFrame>;
  if (!run) return null;

  return (
    <main className="command-app" aria-label="Shieldline command center">
      <header className="command-header">
        <button className="icon-action" type="button" onClick={() => setScreen("modes")} aria-label="Back to modes"><ArrowLeft size={20} /></button>
        <div className="command-brand"><BrandMark size={25} /><span>Shieldline</span><small>City 01 · Night 01</small></div>
        <span className={`outcome outcome--${run.result}`}>{run.result === "victory" ? "Contained" : run.result}</span>
      </header>
      <section className="command-content">
        {screen === "operation" ? <OperationLoading /> : null}
        {screen === "report" ? <AfterAction run={run} /> : null}
      </section>
      <BottomNav active={activeTab} onChange={setActiveTab} />
    </main>
  );
}

function ModeCatalog({ onSelect, campaign, unlockedMissionIndex }: { onSelect: (id: GameModeId, missionIndex?: number) => void; campaign: ReturnType<typeof useGameStore.getState>["game"]["campaign"]; unlockedMissionIndex: number }) {
  const { profile } = useAuth();
  const [accountOpen, setAccountOpen] = useState(false);
  const [notificationState, setNotificationState] = useState<"idle" | "enabled" | "unavailable">("idle");
  const enableNotifications = async () => setNotificationState(await setTelegramNotificationPreference(import.meta.env.BASE_URL, true) ? "enabled" : "unavailable");
  const campaignMode = gameModes.find((mode) => mode.id === "campaign")!;
  return <main className="command-app command-app--catalog" aria-label="Shieldline mode selection">
    <header className="catalog-hero">
      <button className="catalog-profile-button" type="button" onClick={() => setAccountOpen(true)} aria-label="Відкрити профіль"><UserRound size={17} /><span>{profile.nickname}</span></button>
      <div className="catalog-brand"><BrandMark size={30} /><strong>ShieldLine</strong></div>
      <span className="hero-chip"><Radio size={14} /> {t("catalog.eyebrow")}</span>
      <h1>{t("catalog.title")}</h1>
      <p>{t("catalog.lead")}</p>
      {typeof window !== "undefined" && window.Telegram?.WebApp?.initData ? <button className="telegram-notification-button" type="button" onClick={enableNotifications} disabled={notificationState === "enabled"}>{notificationState === "enabled" ? "Telegram notifications enabled" : notificationState === "unavailable" ? "Telegram authorization unavailable" : "Enable Telegram reports"}</button> : null}
    </header>
    <section className="mode-catalog mode-catalog--campaign-only" aria-label="Available game modes">
      {[campaignMode].map((mode) => {
        const Icon = icons[mode.id];
        return <div className="command-mode-stack" key={mode.id}><button className="command-mode-card" type="button" onClick={() => onSelect(mode.id, unlockedMissionIndex)}>
          <span className="mode-icon"><Icon size={21} /></span>
          <span className="mode-card-top"><small>{mode.eyebrow}</small>{mode.availability === "preview" ? <i>Foundation ready</i> : <i className="mode-live">Play</i>}</span>
          <strong>{t("catalog.campaign")}</strong><p>{t("catalog.campaignDesc")}</p>
          <span className="mode-facts"><b><Clock3 size={14} />{mode.duration}</b><b><Activity size={14} />{mode.difficulty}</b></span>
          <span className="mode-detail"><b>{t("catalog.resources")}</b>{mode.resources}</span>
          <span className="mode-detail"><b>{t("catalog.risk")}</b>{mode.mainRisk}</span>
          <span className="mode-detail"><b>{t("catalog.victory")}</b>{mode.victory}</span>
          <span className="mode-go">{t("catalog.open")} <ChevronRight size={17} /></span>
        </button><section className="campaign-mission-picker" aria-label="Вибір місії кампанії"><header><strong>Місії кампанії</strong><span>Прогрес зберігається автоматично</span></header><div>{campaignMissions.map((mission, index) => {
          const missionIndex = index + 1;
          const completed = Boolean(campaign?.previousMissionResults.some((result) => result.missionIndex === missionIndex));
          const available = missionIndex === unlockedMissionIndex && !completed;
          const locked = missionIndex > unlockedMissionIndex;
          return <button className={completed ? "is-completed" : available ? "is-available" : ""} type="button" key={mission.id} disabled={!available} onClick={() => onSelect("campaign", missionIndex)}><span>{completed ? <Check size={15} /> : locked ? <Lock size={14} /> : <Play size={14} />} Місія {missionIndex}</span><strong>{mission.title}</strong><small>{completed ? "Пройдена" : available ? campaign ? "Продовжити" : "Доступна" : "Заблокована"}</small></button>;
        })}</div></section></div>;
      })}
    </section>
    <p className="catalog-roadmap-note">{t("catalog.paused")}</p>
    {accountOpen ? <AccountSettings modal onClose={() => setAccountOpen(false)} /> : null}
  </main>;
}

function Briefing({ modeId, missionIndex, onBack, onStart, isRunning }: { modeId: GameModeId; missionIndex: number; onBack: () => void; onStart: () => void; isRunning: boolean }) {
  const mode = getGameMode(modeId);
  const mission = modeId === "campaign" ? campaignMissions[missionIndex - 1] || campaignMissions[0] : campaignMissions[0];
  return <main className="command-app" aria-label="Mission briefing">
    <header className="command-header"><button className="icon-action" type="button" onClick={onBack} aria-label="Back"><ArrowLeft size={20} /></button><div className="command-brand"><BrandMark size={25} /><span>Mission briefing</span><small>{mode.title}</small></div></header>
    <section className="briefing-screen">
      <span className="hero-chip"><Waves size={14} /> {mission.subtitle}</span>
      <h1>{modeId === "campaign" ? mission.title : mode.title}</h1>
      <p className="briefing-lead">{modeId === "campaign" ? mission.briefing : mode.description}</p>
      <section className="briefing-facts"><Fact label="Тривалість" value={`${mission.durationMinutes} хв`} /><Fact label="Основний театр" value={mission.focusRegion || mission.mainRisk} /><Fact label="Очікувані загрози" value={mission.expectedThreatClasses?.join(" · ") || mission.mainRisk} /><Fact label="Широкий азимут" value={mission.broadAzimuth || "невизначений"} /><Fact label="Завдання" value={mission.victoryCondition} /></section>
      <section className="reserve-bar"><span>Кампанійний резерв</span><b>Грант {mission.grant || mission.resources.budget} млн ₴</b><b>Нагорода за кожне збиття</b><b>Стійкість 100%</b></section>
      <button className="primary-command" type="button" onClick={onStart} disabled={isRunning}><Play size={19} />{isRunning ? "Synchronizing command…" : modeId === "daily-defense" ? "Open daily report" : "Open manual command board"}</button>
      <small className="briefing-note">All primary modes start with your manual placement and planning. Only Daily Defense resolves its prepared city automatically once per day.</small>
    </section>
  </main>;
}

function OperationLoading() { return <section className="operation-loading"><div className="scan-ring"><Radio size={38} /></div><h1>Night simulation resolved</h1><p>Building after-action report from the immutable event stream.</p></section>; }

function CommandFrame({ onBack, children }: { onBack: () => void; children: ReactNode }) { return <main className="command-app" aria-label="Shieldline command center"><header className="command-header"><button className="icon-action" type="button" onClick={onBack} aria-label="Back to modes"><ArrowLeft size={20} /></button><div className="command-brand"><BrandMark size={25} /><span>Shieldline</span><small>City 01 · command view</small></div></header><section className="command-content">{children}</section><BottomNav active="operations" onChange={() => undefined} /></main>; }

function DailyDefense({ report, run }: { report: DailyReport | null; run: MissionRun | null }) { const launchDailyBoard = () => { const state = useGameStore.getState(); state.launchTacticalMode("daily-defense"); const url = new URL(window.location.href); url.searchParams.set("legacy", "1"); url.searchParams.set("mode", "daily-defense"); window.location.assign(url.toString()); }; return <section className="report-screen" aria-label="Daily defense report"><span className="hero-chip"><Home size={14} /> Daily Defense · city persists</span><h1>Morning report</h1><p>{report?.summary || "The daily command report is being prepared."} Your repair and doctrine decisions are ready for the next night.</p>{run ? <><SectorMap summary={run.sectorSummary} /><section className="recommendation"><Flag size={19} /><div><strong>Daily command</strong><span>{report?.recommendedAction}</span></div></section><button className="primary-command" type="button" onClick={launchDailyBoard}><Shield size={19} /> Open city planning board</button></> : null}</section>; }
function Ranking({ entries }: { entries: LeaderboardEntry[] }) { return <section className="report-screen ranking-screen" aria-label="Ranked challenge leaderboard"><span className="hero-chip"><Trophy size={14} /> Ranked Challenge · shared results</span><h1>Daily ranking</h1><p>Each run is scored from its server-side event stream. Cosmetic and convenience features never change combat power.</p><ol>{entries.length ? entries.map((entry) => <li key={`${entry.userId}-${entry.rank}`}><b>#{entry.rank}</b><span>{entry.displayName}</span><em>{entry.result}</em><strong>{entry.score}</strong></li>) : <li><span>No completed ranked runs yet.</span></li>}</ol></section>; }
function Coop({ room, onClaim, onEnter }: { room: CoOpRoom | null; onClaim: (sectorId: SectorId) => void; onEnter: (sectorId: SectorId) => void }) { const sectors: SectorId[] = ["north", "south", "east", "west"]; const viewerRole = room?.members.find((member) => member.userId === room.viewerId)?.role; return <section className="report-screen coop-screen" aria-label="Async co-op command room"><span className="hero-chip"><Users size={14} /> Co-op Command · async room</span><h1>Kyiv-01</h1><p>Claim one sector. Every placement on the tactical map is validated against that role and appended to the HQ log.</p><div className="coop-grid">{sectors.map((sector) => <button key={sector} type="button" onClick={() => onClaim(sector)} disabled={Boolean(room?.sectorAssignments[sector])}><span>{sector}</span><b>{room?.sectorAssignments[sector] || "Claim sector"}</b></button>)}</div>{viewerRole && viewerRole !== "hq" ? <button className="primary-command" type="button" onClick={() => onEnter(viewerRole)}><Shield size={19} /> Enter {viewerRole} command board</button> : null}<section className="recommendation"><Command size={19} /><div><strong>HQ feed · revision {room?.revision || 0}</strong><span>{room?.commandLog.at(-1)?.message || "Awaiting sector commands."}</span></div></section></section>; }

function AfterAction({ run }: { run: MissionRun }) {
  const title = run.result === "victory" ? "Night held" : run.result === "contained" ? "Pressure contained" : "Defense setback";
  return <section className="report-screen" aria-label="After-action report"><span className="hero-chip"><FileText size={14} /> After-action report · deterministic run</span><h1>{title}</h1><p>{run.interceptions} intercepts and {run.impacts} impacts were resolved from one reproducible seed. The next campaign decision can build on this result.</p><div className="result-grid"><Result icon={Crosshair} value={run.interceptions} label="Intercepts" /><Result icon={Zap} value={run.impacts} label="Impacts" /><Result icon={Command} value={run.ammoSpent} label="Ammo spent" /></div><SectorMap summary={run.sectorSummary} /><section className="recommendation"><Flag size={19} /><div><strong>Command recommendation</strong><span>Reinforce East before the next night; keep the HQ reserve available for mixed tracks.</span></div></section></section>;
}

function SectorMap({ summary }: { summary: MissionRun["sectorSummary"] }) { return <section className="sector-report-map" aria-label="Sector result map">{(Object.keys(summary) as Array<keyof typeof summary>).map((id) => <div className={`sector-result sector-result--${id}`} key={id}><span>{sectorNames[id]}</span><b>{summary[id].coverage}% cover</b><small>{summary[id].damage ? `${summary[id].damage}% damage` : "stable"}</small></div>)}<div className="sector-result sector-result--center"><Shield size={20} /><b>HQ</b></div></section>; }
function Fact({ label, value }: { label: string; value: string }) { return <div><span>{label}</span><b>{value}</b></div>; }
function Result({ icon: Icon, value, label }: { icon: typeof Crosshair; value: number; label: string }) { return <div><Icon size={18} /><strong>{value}</strong><span>{label}</span></div>; }
function BottomNav({ active, onChange }: { active: Tab; onChange: (tab: Tab) => void }) { const items: Array<{ id: Tab; label: string; icon: typeof Home }> = [{ id: "city", label: "City", icon: Home }, { id: "operations", label: "Ops", icon: Swords }, { id: "squad", label: "Squad", icon: Users }, { id: "rating", label: "Rating", icon: BarChart3 }, { id: "reports", label: "Reports", icon: FileText }]; return <nav className="bottom-command-nav" aria-label="Command sections">{items.map(({ id, label, icon: Icon }) => <button className={active === id ? "bottom-command-nav__active" : ""} type="button" key={id} onClick={() => onChange(id)}><Icon size={18} /><span>{label}</span></button>)}</nav>; }
