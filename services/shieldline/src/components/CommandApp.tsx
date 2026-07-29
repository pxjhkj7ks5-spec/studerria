import { useEffect, useState, type ReactNode } from "react";
import { ArrowLeft, BarChart3, Check, Clock3, Command, FileText, Flag, Home, Lock, MapPin, Play, Radio, Shield, Swords, Target, Trophy, UserRound, Users, WalletCards, Waves } from "lucide-react";
import { AccountSettings } from "./AccountSettings";
import { BrandMark } from "./BrandMark";
import { useAuth } from "./AuthGate";
import { apiGameRepository } from "../data/apiGameRepository";
import { getGameMode } from "../data/gameModes";
import { campaignMissions } from "../data/missions";
import { buildCampaignCatalogPresentation, localizeThreatClass } from "../game/campaignPresentation";
import { setTelegramNotificationPreference, telegramCommandFeedback } from "../platform/telegramShell";
import { trackAnalytics } from "../platform/analytics";
import { useGameStore } from "../store/useGameStore";
import { unlockedCampaignMissionIndex } from "../game/campaignMeta";
import type { CoOpRoom, DailyReport, GameModeId, LeaderboardEntry, MissionRun, SectorId } from "../domain/contracts";

type Screen = "modes" | "briefing" | "daily" | "ranking" | "coop";
type Tab = "city" | "operations" | "squad" | "rating" | "reports";

const sectorNames: Record<Exclude<SectorId, "hq">, string> = { north: "North", south: "South", east: "East", west: "West" };

export function CommandApp() {
  const [screen, setScreen] = useState<Screen>("modes");
  const [selectedMode, setSelectedMode] = useState<GameModeId>("campaign");
  const [selectedCampaignMission, setSelectedCampaignMission] = useState(1);
  const [run, setRun] = useState<MissionRun | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [dailyReport, setDailyReport] = useState<DailyReport | null>(null);
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [room, setRoom] = useState<CoOpRoom | null>(null);
  const launchTacticalMode = useGameStore((state) => state.launchTacticalMode);
  const openCampaignMission = useGameStore((state) => state.openCampaignMission);
  const game = useGameStore((state) => state.game);
  const campaign = game.campaign;
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

  if (screen === "modes") return <ModeCatalog onSelect={selectMode} game={game} />;
  if (screen === "briefing") return <Briefing modeId={selectedMode} missionIndex={selectedCampaignMission} onBack={() => setScreen("modes")} onStart={runMission} isRunning={isRunning} />;
  if (screen === "ranking") return <CommandFrame onBack={() => setScreen("modes")}><Ranking entries={leaderboard} /></CommandFrame>;
  if (screen === "coop") return <CommandFrame onBack={() => setScreen("modes")}><Coop room={room} onClaim={async (sectorId) => setRoom(await apiGameRepository.claimCoOpSector("kyiv-01", sectorId))} onEnter={(sectorId) => { window.sessionStorage.setItem("shieldline-coop-session", JSON.stringify({ roomId: "kyiv-01", sectorId })); openManualCommand("co-op-command"); }} /></CommandFrame>;
  if (screen === "daily") return <CommandFrame onBack={() => setScreen("modes")}><DailyDefense report={dailyReport} run={run} /></CommandFrame>;
  return null;
}

function ModeCatalog({ onSelect, game }: { onSelect: (id: GameModeId, missionIndex?: number) => void; game: ReturnType<typeof useGameStore.getState>["game"] }) {
  const { profile } = useAuth();
  const [accountOpen, setAccountOpen] = useState(false);
  const [notificationState, setNotificationState] = useState<"idle" | "enabled" | "unavailable">("idle");
  const enableNotifications = async () => setNotificationState(await setTelegramNotificationPreference(import.meta.env.BASE_URL, true) ? "enabled" : "unavailable");
  const presentation = buildCampaignCatalogPresentation(game);
  const { mission } = presentation;
  return <main className="command-app command-app--catalog" data-audio-scope="player" aria-label="Головне меню ShieldLine">
    <header className="catalog-hero">
      <button className="catalog-profile-button" type="button" onClick={() => setAccountOpen(true)} aria-label="Відкрити профіль"><UserRound size={17} /><span>{profile.nickname}</span></button>
      <div className="catalog-brand"><BrandMark size={30} /><strong>ShieldLine</strong></div>
      <span className="hero-chip"><Radio size={14} /> Командний центр</span>
      <h1>Утримайте рубіж.</h1>
      <p>П’ять послідовних операцій. Кожне рішення, втрата й зароблена гривня переходять у наступну місію.</p>
      {typeof window !== "undefined" && window.Telegram?.WebApp?.initData ? <button className="telegram-notification-button" type="button" onClick={enableNotifications} disabled={notificationState === "enabled"}>{notificationState === "enabled" ? "Звіти Telegram увімкнено" : notificationState === "unavailable" ? "Авторизація Telegram недоступна" : "Увімкнути звіти в Telegram"}</button> : null}
    </header>
    <section className="campaign-overview" aria-label="Кампанія">
      <article className="active-operation">
        <span className="active-operation__eyebrow">Місія {presentation.currentIndex} з 5</span>
        <h2>{mission.title}</h2>
        <p>{mission.victoryCondition}</p>
        <div className="campaign-vitals" aria-label="Стан кампанії">
          <span><WalletCards size={17} /><small>Гаманець</small><strong>{presentation.wallet} млн ₴</strong></span>
          <span><Command size={17} /><small>Склад БК</small><strong>{presentation.depotStock}</strong></span>
          <span><Shield size={17} /><small>Найнижчий HP</small><strong>{presentation.minimumCityHp}%</strong></span>
        </div>
        <button className="primary-command active-operation__cta" type="button" disabled={presentation.completed} onClick={() => onSelect("campaign", presentation.currentIndex)}><Play size={19} />{presentation.ctaLabel}</button>
      </article>
      <section className="campaign-progress" aria-label="Прогрес кампанії">
        <header><div><span>Прогрес кампанії</span><strong>{presentation.completedCount} з 5 місій</strong></div><b>{presentation.progressPercent}%</b></header>
        <div className="campaign-progress__bar" aria-hidden="true"><i style={{ width: `${presentation.progressPercent}%` }} /></div>
        <ol>{presentation.timeline.map((item) => <li className={`campaign-step campaign-step--${item.state}`} key={item.mission.id}>
          <button type="button" disabled={item.state !== "current" || presentation.completed} onClick={() => onSelect("campaign", item.missionIndex)}>
            <span className="campaign-step__marker">{item.state === "completed" ? <Check size={14} /> : item.state === "locked" ? <Lock size={13} /> : <span />}</span>
            <span><small>Місія {item.missionIndex}</small><strong>{item.mission.title}</strong></span>
            <em>{item.state === "completed" ? "Завершена" : item.state === "current" ? "Поточна" : "Заблокована"}</em>
          </button>
        </li>)}</ol>
      </section>
    </section>
    {accountOpen ? <AccountSettings modal onClose={() => setAccountOpen(false)} /> : null}
  </main>;
}

function Briefing({ modeId, missionIndex, onBack, onStart, isRunning }: { modeId: GameModeId; missionIndex: number; onBack: () => void; onStart: () => void; isRunning: boolean }) {
  const mode = getGameMode(modeId);
  const mission = modeId === "campaign" ? campaignMissions[missionIndex - 1] || campaignMissions[0] : campaignMissions[0];
  return <main className="command-app" data-audio-scope="player" aria-label="Передмісійний брифінг">
    <header className="command-header"><button className="icon-action" type="button" onClick={onBack} aria-label="Назад"><ArrowLeft size={20} /></button><div className="command-brand"><BrandMark size={25} /><span>Передмісійний брифінг</span><small>{modeId === "campaign" ? `Місія ${missionIndex} з 5` : mode.title}</small></div></header>
    <section className="briefing-screen briefing-screen--campaign">
      <span className="hero-chip"><Waves size={14} /> {modeId === "campaign" ? `Місія ${missionIndex} з 5` : mode.title}</span>
      <h1>{modeId === "campaign" ? mission.title : mode.title}</h1>
      <p className="briefing-lead">{modeId === "campaign" ? mission.briefing : mode.description}</p>
      {modeId === "campaign" && mission.attackRegionHint ? <section className="briefing-attack-zone"><MapPin size={22} /><div><span>Ймовірний район атаки</span><strong>{mission.focusRegion}</strong><p>{mission.attackRegionHint}</p><small>Широкий азимут: {mission.broadAzimuth}</small></div></section> : null}
      <section className="briefing-facts briefing-facts--clean">
        <Fact icon={<Clock3 size={17} />} label="Тривалість" value={`${mission.durationMinutes} хв`} />
        <Fact icon={<Target size={17} />} label="Типи загроз" value={mission.expectedThreatClasses?.map(localizeThreatClass).join(" · ") || mission.mainRisk} />
        <Fact icon={<WalletCards size={17} />} label="Грант" value={`${mission.grant || mission.resources.budget} млн ₴`} />
        <Fact icon={<Command size={17} />} label="Боєкомплект" value="10 БК · повні магазини" />
        <Fact icon={<Flag size={17} />} label="Завдання місії" value={mission.victoryCondition} wide />
      </section>
      {mission.briefingHighlights?.length ? <section className="briefing-highlights" aria-label="Важливі підказки">{mission.briefingHighlights.slice(0, 2).map((highlight) => <p key={highlight}><Check size={16} />{highlight}</p>)}</section> : null}
      <footer className="briefing-launch">
        <button className="primary-command" type="button" onClick={onStart} disabled={isRunning}><Play size={19} />{isRunning ? "Відкриваємо командну мапу…" : modeId === "daily-defense" ? "Відкрити щоденний звіт" : "Перейти до розгортання"}</button>
        <small className="briefing-note">Бій почнеться лише після вашого підтвердження на мапі.</small>
      </footer>
    </section>
  </main>;
}

function CommandFrame({ onBack, children }: { onBack: () => void; children: ReactNode }) { return <main className="command-app" data-audio-scope="player" aria-label="Shieldline command center"><header className="command-header"><button className="icon-action" type="button" onClick={onBack} aria-label="Back to modes"><ArrowLeft size={20} /></button><div className="command-brand"><BrandMark size={25} /><span>Shieldline</span><small>City 01 · command view</small></div></header><section className="command-content">{children}</section><BottomNav active="operations" onChange={() => undefined} /></main>; }

function DailyDefense({ report, run }: { report: DailyReport | null; run: MissionRun | null }) { const launchDailyBoard = () => { const state = useGameStore.getState(); state.launchTacticalMode("daily-defense"); const url = new URL(window.location.href); url.searchParams.set("legacy", "1"); url.searchParams.set("mode", "daily-defense"); window.location.assign(url.toString()); }; return <section className="report-screen" aria-label="Daily defense report"><span className="hero-chip"><Home size={14} /> Daily Defense · city persists</span><h1>Morning report</h1><p>{report?.summary || "The daily command report is being prepared."} Your repair and doctrine decisions are ready for the next night.</p>{run ? <><SectorMap summary={run.sectorSummary} /><section className="recommendation"><Flag size={19} /><div><strong>Daily command</strong><span>{report?.recommendedAction}</span></div></section><button className="primary-command" type="button" onClick={launchDailyBoard}><Shield size={19} /> Open city planning board</button></> : null}</section>; }
function Ranking({ entries }: { entries: LeaderboardEntry[] }) { return <section className="report-screen ranking-screen" aria-label="Ranked challenge leaderboard"><span className="hero-chip"><Trophy size={14} /> Ranked Challenge · shared results</span><h1>Daily ranking</h1><p>Each run is scored from its server-side event stream. Cosmetic and convenience features never change combat power.</p><ol>{entries.length ? entries.map((entry) => <li key={`${entry.userId}-${entry.rank}`}><b>#{entry.rank}</b><span>{entry.displayName}</span><em>{entry.result}</em><strong>{entry.score}</strong></li>) : <li><span>No completed ranked runs yet.</span></li>}</ol></section>; }
function Coop({ room, onClaim, onEnter }: { room: CoOpRoom | null; onClaim: (sectorId: SectorId) => void; onEnter: (sectorId: SectorId) => void }) { const sectors: SectorId[] = ["north", "south", "east", "west"]; const viewerRole = room?.members.find((member) => member.userId === room.viewerId)?.role; return <section className="report-screen coop-screen" aria-label="Async co-op command room"><span className="hero-chip"><Users size={14} /> Co-op Command · async room</span><h1>Kyiv-01</h1><p>Claim one sector. Every placement on the tactical map is validated against that role and appended to the HQ log.</p><div className="coop-grid">{sectors.map((sector) => <button key={sector} type="button" onClick={() => onClaim(sector)} disabled={Boolean(room?.sectorAssignments[sector])}><span>{sector}</span><b>{room?.sectorAssignments[sector] || "Claim sector"}</b></button>)}</div>{viewerRole && viewerRole !== "hq" ? <button className="primary-command" type="button" onClick={() => onEnter(viewerRole)}><Shield size={19} /> Enter {viewerRole} command board</button> : null}<section className="recommendation"><Command size={19} /><div><strong>HQ feed · revision {room?.revision || 0}</strong><span>{room?.commandLog.at(-1)?.message || "Awaiting sector commands."}</span></div></section></section>; }


function SectorMap({ summary }: { summary: MissionRun["sectorSummary"] }) { return <section className="sector-report-map" aria-label="Sector result map">{(Object.keys(summary) as Array<keyof typeof summary>).map((id) => <div className={`sector-result sector-result--${id}`} key={id}><span>{sectorNames[id]}</span><b>{summary[id].coverage}% cover</b><small>{summary[id].damage ? `${summary[id].damage}% damage` : "stable"}</small></div>)}<div className="sector-result sector-result--center"><Shield size={20} /><b>HQ</b></div></section>; }
function Fact({ icon, label, value, wide = false }: { icon?: ReactNode; label: string; value: string; wide?: boolean }) { return <div className={wide ? "briefing-fact--wide" : ""}>{icon}<span>{label}</span><b>{value}</b></div>; }
function BottomNav({ active, onChange }: { active: Tab; onChange: (tab: Tab) => void }) { const items: Array<{ id: Tab; label: string; icon: typeof Home }> = [{ id: "city", label: "City", icon: Home }, { id: "operations", label: "Ops", icon: Swords }, { id: "squad", label: "Squad", icon: Users }, { id: "rating", label: "Rating", icon: BarChart3 }, { id: "reports", label: "Reports", icon: FileText }]; return <nav className="bottom-command-nav" aria-label="Command sections">{items.map(({ id, label, icon: Icon }) => <button className={active === id ? "bottom-command-nav__active" : ""} type="button" key={id} onClick={() => onChange(id)}><Icon size={18} /><span>{label}</span></button>)}</nav>; }
