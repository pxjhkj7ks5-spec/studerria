import type { IntelEntry } from "../types/game";

export const BATTLE_NOTICE_DURATION_MS = 4_000;

export function preferBattleNotice(current: IntelEntry | null, incoming: IntelEntry) {
  if (current?.eventType === "launch" && incoming.eventType === "detection") return current;
  return incoming;
}
