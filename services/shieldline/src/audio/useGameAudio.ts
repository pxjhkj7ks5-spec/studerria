import { useEffect, useRef } from "react";
import type { GameState, IntelEntry } from "../types/game";
import type { OperationPhase } from "../domain/contracts";
import type { AudioPreferences } from "../platform/audioPreferences";
import { playSound, shieldlineAudio } from "./audioEngine";

interface GameAudioInput {
  game: GameState;
  operationPhase: OperationPhase;
  simulationSeed: string;
  preferences: AudioPreferences;
}

export function completionCue(game: GameState) {
  if (game.campaign?.completed && game.status === "won") return "result.campaign-complete" as const;
  if (game.status === "lost") return "result.mission-failure" as const;
  return "result.mission-success" as const;
}

export function collectUnseenSoundCues(entries: IntelEntry[], seenIds: ReadonlySet<string>) {
  return entries
    .filter((entry) => !seenIds.has(entry.id) && entry.soundCue)
    .reverse()
    .map((entry) => entry.soundCue!);
}

export function useGameAudio({ game, operationPhase, simulationSeed, preferences }: GameAudioInput) {
  const gameRef = useRef(game);
  const seenLogIds = useRef(new Set(game.log.map((entry) => entry.id)));
  const previousPhase = useRef(operationPhase);
  const airRaidActive = useRef(game.cities.some((city) => city.alertState === "air-raid"));
  const previousSeed = useRef(simulationSeed);
  gameRef.current = game;

  useEffect(() => {
    shieldlineAudio.setPreferences(preferences);
  }, [preferences]);

  useEffect(() => {
    if (previousSeed.current === simulationSeed) return;
    previousSeed.current = simulationSeed;
    seenLogIds.current = new Set(game.log.map((entry) => entry.id));
    previousPhase.current = operationPhase;
    airRaidActive.current = game.cities.some((city) => city.alertState === "air-raid");
  }, [game.cities, game.log, operationPhase, simulationSeed]);

  useEffect(() => {
    const currentIds = new Set(game.log.map((entry) => entry.id));
    if (document.hidden) {
      seenLogIds.current = currentIds;
      return;
    }
    const unseen = collectUnseenSoundCues(game.log, seenLogIds.current);
    seenLogIds.current = currentIds;
    for (const cue of unseen) void playSound(cue);
  }, [game.log]);

  useEffect(() => {
    const previous = previousPhase.current;
    previousPhase.current = operationPhase;
    if (document.hidden || previous === operationPhase) return;
    let outcomeTimer: number | null = null;
    if (operationPhase === "countdown") void playSound("operation.countdown");
    else if (operationPhase === "running" && previous === "countdown") void playSound("operation.start");
    else if (operationPhase === "running" && previous === "paused") void playSound("operation.resume");
    else if (operationPhase === "paused") void playSound("operation.pause");
    else if (operationPhase === "completed") {
      void playSound("operation.complete");
      outcomeTimer = window.setTimeout(() => void playSound(completionCue(gameRef.current)), 420);
    }
    return () => { if (outcomeTimer !== null) window.clearTimeout(outcomeTimer); };
  }, [operationPhase]);

  useEffect(() => {
    const active = game.cities.some((city) => city.alertState === "air-raid");
    const wasActive = airRaidActive.current;
    airRaidActive.current = active;
    if (document.hidden || active === wasActive) return;
    void playSound(active ? "alert.air-raid" : "alert.clear");
  }, [game.cities]);
}

export function installPlayerAudioInteractions() {
  if (typeof document === "undefined") return () => undefined;
  const playerScope = "[data-audio-scope='player']";
  const unlock = (event: Event) => {
    if (!(event.target instanceof Element) || !event.target.closest(playerScope)) return;
    void shieldlineAudio.unlock();
  };
  const click = (event: Event) => {
    if (!(event.target instanceof Element)) return;
    const control = event.target.closest<HTMLElement>("button, [role='button'], select, input[type='checkbox'], input[type='range']");
    if (!control || !control.closest(playerScope) || control.matches(":disabled") || control.dataset.sound === "none") return;
    const explicitCue = control.dataset.soundCue;
    if (explicitCue) void playSound(explicitCue as Parameters<typeof playSound>[0]);
    else if (!control.matches("input[type='range']")) void playSound("ui.select");
  };
  const visibility = () => shieldlineAudio.setVisible(!document.hidden);
  document.addEventListener("pointerdown", unlock, true);
  document.addEventListener("keydown", unlock, true);
  document.addEventListener("click", click, true);
  document.addEventListener("visibilitychange", visibility);
  return () => {
    document.removeEventListener("pointerdown", unlock, true);
    document.removeEventListener("keydown", unlock, true);
    document.removeEventListener("click", click, true);
    document.removeEventListener("visibilitychange", visibility);
  };
}
