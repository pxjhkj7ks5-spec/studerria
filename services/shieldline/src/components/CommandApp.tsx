import { useEffect, useState, type CSSProperties } from "react";
import { Activity, ArrowLeft, BarChart3, ChevronRight, CircleHelp, Clock3, Command, Crosshair, FileText, Flag, Gamepad2, Headphones, Home, Play, Radio, RotateCcw, Shield, ShieldCheck, Swords, Trophy, Users, Waves, Zap } from "lucide-react";
import { localGameRepository } from "../data/localGameRepository";
import { gameModes, getGameMode } from "../data/gameModes";
import { campaignMissions } from "../data/missions";
import type { GameModeId, MissionRun, ReplayEvent, SectorId } from "../domain/contracts";

type Screen = "modes" | "briefing" | "operation" | "report" | "replay";
type Tab = "city" | "operations" | "squad" | "rating" | "reports";

const icons: Record<GameModeId, typeof Shield> = { campaign: Swords, "daily-defense": Home, "ranked-challenge": Trophy, "co-op-command": Users, sandbox: Gamepad2, training: CircleHelp };
const sectorNames: Record<Exclude<SectorId, "hq">, string> = { north: "North", south: "South", east: "East", west: "West" };

export function CommandApp() {
  const [screen, setScreen] = useState<Screen>("modes");
  const [selectedMode, setSelectedMode] = useState<GameModeId>("campaign");
  const [run, setRun] = useState<MissionRun | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("operations");
  const [replayIndex, setReplayIndex] = useState(0);
  const [isRunning, setIsRunning] = useState(false);
  const mission = campaignMissions[0];
  const replayEvent = run?.replay[replayIndex];

  useEffect(() => {
    if (screen !== "replay" || !run) return undefined;
    const timer = window.setInterval(() => setReplayIndex((value) => (value + 1) % run.replay.length), 1200);
    return () => window.clearInterval(timer);
  }, [screen, run]);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "auto" });
  }, [screen]);

  const selectMode = (id: GameModeId) => {
    setSelectedMode(id);
    setScreen(id === "campaign" ? "briefing" : "briefing");
  };

  const runMission = async () => {
    setIsRunning(true);
    // This local async call is the single seam to replace with the authoritative API.
    const nextRun = await localGameRepository.runMission(mission, `local-${new Date().toISOString().slice(0, 10)}`);
    setRun(nextRun);
    setIsRunning(false);
    setScreen("operation");
    window.setTimeout(() => setScreen("report"), 1250);
  };

  if (screen === "modes") return <ModeCatalog onSelect={selectMode} />;
  if (screen === "briefing") return <Briefing modeId={selectedMode} onBack={() => setScreen("modes")} onStart={runMission} isRunning={isRunning} />;
  if (!run) return null;

  return (
    <main className="command-app" aria-label="Shieldline command center">
      <header className="command-header">
        <button className="icon-action" type="button" onClick={() => setScreen("modes")} aria-label="Back to modes"><ArrowLeft size={20} /></button>
        <div className="command-brand"><ShieldCheck size={22} /><span>Shieldline</span><small>City 01 · Night 01</small></div>
        <span className={`outcome outcome--${run.result}`}>{run.result === "victory" ? "Contained" : run.result}</span>
      </header>
      <section className="command-content">
        {screen === "operation" ? <OperationLoading /> : null}
        {screen === "report" ? <AfterAction run={run} onReplay={() => { setReplayIndex(0); setScreen("replay"); }} /> : null}
        {screen === "replay" ? <Replay run={run} current={replayEvent} index={replayIndex} onChange={setReplayIndex} onBack={() => setScreen("report")} /> : null}
      </section>
      <BottomNav active={activeTab} onChange={setActiveTab} />
    </main>
  );
}

function ModeCatalog({ onSelect }: { onSelect: (id: GameModeId) => void }) {
  return <main className="command-app command-app--catalog" aria-label="Shieldline mode selection">
    <header className="catalog-hero">
      <span className="hero-chip"><Radio size={14} /> Telegram-first command sim</span>
      <h1>One city. One night.<br /><em>Your command.</em></h1>
      <p>A mobile strategy simulation built for Telegram Mini App, browser and installable PWA. Every outcome is fictional, abstract and replayable.</p>
    </header>
    <section className="mode-catalog" aria-label="Game modes">
      {gameModes.map((mode) => {
        const Icon = icons[mode.id];
        return <button className="command-mode-card" type="button" key={mode.id} onClick={() => onSelect(mode.id)}>
          <span className="mode-icon"><Icon size={21} /></span>
          <span className="mode-card-top"><small>{mode.eyebrow}</small>{mode.availability === "preview" ? <i>Foundation ready</i> : <i className="mode-live">Play</i>}</span>
          <strong>{mode.title}</strong><p>{mode.description}</p>
          <span className="mode-facts"><b><Clock3 size={14} />{mode.duration}</b><b><Activity size={14} />{mode.difficulty}</b></span>
          <span className="mode-detail"><b>Resources</b>{mode.resources}</span>
          <span className="mode-detail"><b>Main risk</b>{mode.mainRisk}</span>
          <span className="mode-detail"><b>Victory</b>{mode.victory}</span>
          <span className="mode-go">Open briefing <ChevronRight size={17} /></span>
        </button>;
      })}
    </section>
  </main>;
}

function Briefing({ modeId, onBack, onStart, isRunning }: { modeId: GameModeId; onBack: () => void; onStart: () => void; isRunning: boolean }) {
  const mode = getGameMode(modeId);
  const mission = campaignMissions[0];
  const launchable = modeId === "campaign";
  return <main className="command-app" aria-label="Mission briefing">
    <header className="command-header"><button className="icon-action" type="button" onClick={onBack} aria-label="Back"><ArrowLeft size={20} /></button><div className="command-brand"><ShieldCheck size={22} /><span>Mission briefing</span><small>{mode.title}</small></div></header>
    <section className="briefing-screen">
      <span className="hero-chip"><Waves size={14} /> {mission.subtitle}</span>
      <h1>{launchable ? mission.title : mode.title}</h1>
      <p className="briefing-lead">{launchable ? mission.briefing : "The game contract and mobile shell are ready for this mode. Its shared or scheduled server workflow will attach to the same event stream after Campaign validation."}</p>
      <section className="briefing-sector-map" aria-label="City sector map">
        <span className="sector sector--north">North <b>72%</b></span><span className="sector sector--west">West <b>74%</b></span><span className="sector sector--hq">HQ <Shield size={18} /></span><span className="sector sector--east sector--risk">East <b>68%</b></span><span className="sector sector--south">South <b>61%</b></span>
        <i className="route route--east" /><i className="route route--north" /><i className="route route--south" />
      </section>
      <section className="briefing-facts"><Fact label="Duration" value={`${mission.durationMinutes} min at x${mission.simulationSpeed}`} /><Fact label="Difficulty" value={mission.difficulty} /><Fact label="Main risk" value={mission.mainRisk} /><Fact label="Win condition" value={mission.victoryCondition} /></section>
      <section className="reserve-bar"><span>Reserve</span><b>Ammo {mission.resources.ammo}</b><b>Morale {mission.resources.morale}%</b><b>Energy {mission.resources.energy}%</b></section>
      <button className="primary-command" type="button" onClick={launchable ? onStart : onBack} disabled={isRunning}><Play size={19} />{isRunning ? "Running server-equivalent simulation…" : launchable ? "Begin night operation" : "Return to command modes"}</button>
      <small className="briefing-note">Local prototype uses a deterministic seed and append-only events. In production the same command resolves server-side.</small>
    </section>
  </main>;
}

function OperationLoading() { return <section className="operation-loading"><div className="scan-ring"><Radio size={38} /></div><h1>Night simulation resolved</h1><p>Building after-action report from the immutable event stream.</p></section>; }

function AfterAction({ run, onReplay }: { run: MissionRun; onReplay: () => void }) {
  const title = run.result === "victory" ? "Night held" : run.result === "contained" ? "Pressure contained" : "Defense setback";
  return <section className="report-screen" aria-label="After-action report"><span className="hero-chip"><FileText size={14} /> After-action report · deterministic run</span><h1>{title}</h1><p>{run.interceptions} intercepts and {run.impacts} impacts were resolved from one reproducible seed. The next campaign decision can build on this result.</p><div className="result-grid"><Result icon={Crosshair} value={run.interceptions} label="Intercepts" /><Result icon={Zap} value={run.impacts} label="Impacts" /><Result icon={Command} value={run.ammoSpent} label="Ammo spent" /></div><SectorMap summary={run.sectorSummary} /><section className="recommendation"><Flag size={19} /><div><strong>Command recommendation</strong><span>Reinforce East before the next night; keep the HQ reserve available for mixed tracks.</span></div></section><button className="primary-command" type="button" onClick={onReplay}><Play size={19} /> Watch event replay</button><small className="briefing-note">Replay is generated from the same append-only events that create this report.</small></section>;
}

function Replay({ run, current, index, onChange, onBack }: { run: MissionRun; current?: ReplayEvent; index: number; onChange: (value: number) => void; onBack: () => void }) {
  const progress = run.replay.length ? ((index + 1) / run.replay.length) * 100 : 0;
  return <section className="replay-screen" aria-label="Mission replay"><div className="replay-heading"><div><span className="hero-chip"><RotateCcw size={14} /> Replay · seed {run.seed.slice(-10)}</span><h1>Route & intercept timeline</h1></div><button className="secondary-command" type="button" onClick={onBack}>Report</button></div><ReplayMap current={current} /><div className="timeline"><input aria-label="Replay timeline" type="range" min="0" max={Math.max(0, run.replay.length - 1)} value={index} onChange={(event) => onChange(Number(event.target.value))} style={{ "--progress": `${progress}%` } as CSSProperties} /><span>{current ? `${Math.round(current.replayAtMs / 1000)}s · ${current.message}` : "No replay events"}</span></div><ol className="event-log">{run.replay.map((entry, entryIndex) => <li className={entryIndex === index ? "event-log__active" : ""} key={entry.id}><b>{entry.type.replace(".", " ")}</b><span>{entry.message}</span></li>)}</ol></section>;
}

function SectorMap({ summary }: { summary: MissionRun["sectorSummary"] }) { return <section className="sector-report-map" aria-label="Sector result map">{(Object.keys(summary) as Array<keyof typeof summary>).map((id) => <div className={`sector-result sector-result--${id}`} key={id}><span>{sectorNames[id]}</span><b>{summary[id].coverage}% cover</b><small>{summary[id].damage ? `${summary[id].damage}% damage` : "stable"}</small></div>)}<div className="sector-result sector-result--center"><Shield size={20} /><b>HQ</b></div></section>; }
function ReplayMap({ current }: { current?: ReplayEvent }) { const route = current?.route; return <section className="replay-map"><span className="replay-sector replay-sector--north">N</span><span className="replay-sector replay-sector--west">W</span><span className="replay-sector replay-sector--hq"><Shield size={20} /></span><span className="replay-sector replay-sector--east">E</span><span className="replay-sector replay-sector--south">S</span>{route ? <><i className={`replay-route replay-route--${route.from}-to-${route.to}`} /><span className="replay-track">{route.from.toUpperCase()} → {route.to.toUpperCase()}</span></> : null}{current?.interceptPoint ? <i className="intercept-dot" style={{ left: `${current.interceptPoint.x}%`, top: `${current.interceptPoint.y}%` }} /> : null}</section>; }
function Fact({ label, value }: { label: string; value: string }) { return <div><span>{label}</span><b>{value}</b></div>; }
function Result({ icon: Icon, value, label }: { icon: typeof Crosshair; value: number; label: string }) { return <div><Icon size={18} /><strong>{value}</strong><span>{label}</span></div>; }
function BottomNav({ active, onChange }: { active: Tab; onChange: (tab: Tab) => void }) { const items: Array<{ id: Tab; label: string; icon: typeof Home }> = [{ id: "city", label: "City", icon: Home }, { id: "operations", label: "Ops", icon: Swords }, { id: "squad", label: "Squad", icon: Users }, { id: "rating", label: "Rating", icon: BarChart3 }, { id: "reports", label: "Reports", icon: FileText }]; return <nav className="bottom-command-nav" aria-label="Command sections">{items.map(({ id, label, icon: Icon }) => <button className={active === id ? "bottom-command-nav__active" : ""} type="button" key={id} onClick={() => onChange(id)}><Icon size={18} /><span>{label}</span></button>)}</nav>; }
