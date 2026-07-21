import { applyAccountProgressState, readAccountProgressState, useGameStore, type AccountProgressState } from "../store/useGameStore";

type ProgressSnapshot = { revision: number; state: AccountProgressState; updatedAt: string };

let actorId: string | null = null;
let revision: number | null = null;
let unsubscribe: (() => void) | null = null;
let saveTimer: number | null = null;
let saving = false;
let dirty = false;
let applyingRemote = false;
let lastFingerprint = "";

function endpoint() {
  return `${import.meta.env.BASE_URL}api/player/progress`;
}

async function readRemote(): Promise<ProgressSnapshot | null> {
  const response = await fetch(endpoint(), { headers: { Accept: "application/json" } });
  const payload = await response.json().catch(() => ({})) as { progress?: ProgressSnapshot | null; error?: string };
  if (!response.ok) throw new Error(payload.error || "Не вдалося завантажити прогрес.");
  return payload.progress || null;
}

async function writeRemote(baseRevision: number, state: AccountProgressState) {
  const response = await fetch(endpoint(), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ baseRevision, state }),
    keepalive: true,
  });
  const payload = await response.json().catch(() => ({})) as { progress?: ProgressSnapshot; error?: string; latestPatch?: { accountProgress?: ProgressSnapshot | null } };
  if (response.status === 409) return { conflict: payload.latestPatch?.accountProgress || null } as const;
  if (!response.ok || !payload.progress) throw new Error(payload.error || "Не вдалося зберегти прогрес.");
  return { progress: payload.progress } as const;
}

function fingerprint(state: AccountProgressState) {
  return JSON.stringify(state);
}

function applyRemote(snapshot: ProgressSnapshot) {
  applyingRemote = true;
  try {
    if (applyAccountProgressState(snapshot.state)) {
      revision = snapshot.revision;
      lastFingerprint = fingerprint(readAccountProgressState());
      dirty = false;
    }
  } finally { applyingRemote = false; }
}

async function flush() {
  if (!actorId || revision === null || saving || !dirty) return;
  const state = readAccountProgressState();
  const nextFingerprint = fingerprint(state);
  if (nextFingerprint === lastFingerprint) { dirty = false; return; }
  saving = true;
  dirty = false;
  try {
    const result = await writeRemote(revision, state);
    if ("conflict" in result) {
      if (result.conflict) applyRemote(result.conflict);
      else revision = 0;
    } else {
      revision = result.progress.revision;
      lastFingerprint = nextFingerprint;
    }
  } catch {
    dirty = true;
  } finally {
    saving = false;
    if (dirty) scheduleSave();
  }
}

async function refreshLatest() {
  if (!actorId || saving || dirty) return;
  try {
    const remote = await readRemote();
    if (remote && (revision === null || remote.revision > revision)) applyRemote(remote);
  } catch { /* Keep the local snapshot and retry on the next focus/online event. */ }
}

function scheduleSave() {
  if (saveTimer !== null) window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(() => { saveTimer = null; void flush(); }, 1_200);
}

function startWatching() {
  unsubscribe?.();
  unsubscribe = useGameStore.subscribe(() => {
    if (applyingRemote) return;
    dirty = true;
    scheduleSave();
  });
}

export async function initializeAccountProgressSync(nextActorId: string) {
  if (actorId === nextActorId && revision !== null) return;
  actorId = nextActorId;
  revision = null;
  dirty = false;
  unsubscribe?.();
  unsubscribe = null;
  try {
    const remote = await readRemote();
    if (remote) applyRemote(remote);
    else {
      const state = readAccountProgressState();
      const result = await writeRemote(0, state);
      if ("progress" in result && result.progress) {
        revision = result.progress.revision;
        lastFingerprint = fingerprint(state);
      } else if (result.conflict) applyRemote(result.conflict);
    }
  } catch {
    revision = 0;
    dirty = true;
  }
  startWatching();
  if (dirty) scheduleSave();
}

if (typeof window !== "undefined") {
  window.addEventListener("online", () => { if (actorId) void refreshLatest(); });
  window.addEventListener("focus", () => { void refreshLatest(); });
  window.addEventListener("pageshow", () => { void refreshLatest(); });
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") void refreshLatest(); });
  window.addEventListener("pagehide", () => { void flush(); });
}
