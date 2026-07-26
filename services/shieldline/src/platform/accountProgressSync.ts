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
let initialization: { actorId: string; promise: Promise<void> } | null = null;

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

export function resolveProgressWriteConflict<T>(localState: T, conflict: { revision: number; state: T } | null) {
  const remoteFingerprint = conflict ? JSON.stringify(conflict.state) : "";
  return {
    baseRevision: conflict?.revision || 0,
    state: localState,
    remoteFingerprint,
    shouldRetry: JSON.stringify(localState) !== remoteFingerprint,
  };
}

export function canApplyRemoteProgress(state: Pick<AccountProgressState, "operationPhase">) {
  return state.operationPhase !== "countdown" && state.operationPhase !== "running" && state.operationPhase !== "paused";
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
      const resolution = resolveProgressWriteConflict(readAccountProgressState(), result.conflict || null);
      revision = resolution.baseRevision;
      lastFingerprint = resolution.remoteFingerprint;
      dirty = dirty || resolution.shouldRetry;
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
    if (remote && (revision === null || remote.revision > revision)) {
      const localState = readAccountProgressState();
      if (canApplyRemoteProgress(localState)) applyRemote(remote);
      else {
        const resolution = resolveProgressWriteConflict(localState, remote);
        revision = resolution.baseRevision;
        lastFingerprint = resolution.remoteFingerprint;
        dirty = resolution.shouldRetry;
        if (dirty) scheduleSave();
      }
    }
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

export function initializeAccountProgressSync(nextActorId: string) {
  if (actorId === nextActorId && revision !== null) return Promise.resolve();
  if (initialization?.actorId === nextActorId) return initialization.promise;

  const promise = (async () => {
    actorId = nextActorId;
    revision = null;
    dirty = false;
    unsubscribe?.();
    unsubscribe = null;
    try {
      const remote = await readRemote();
      if (actorId !== nextActorId) return;
      if (remote) applyRemote(remote);
      else {
        const state = readAccountProgressState();
        const result = await writeRemote(0, state);
        if (actorId !== nextActorId) return;
        if ("progress" in result && result.progress) {
          revision = result.progress.revision;
          lastFingerprint = fingerprint(state);
        } else if (result.conflict) applyRemote(result.conflict);
      }
    } catch {
      if (actorId !== nextActorId) return;
      revision = 0;
      dirty = true;
    }
    if (actorId !== nextActorId) return;
    startWatching();
    if (dirty) scheduleSave();
  })();

  initialization = { actorId: nextActorId, promise };
  void promise.finally(() => {
    if (initialization?.promise === promise) initialization = null;
  });
  return promise;
}

if (typeof window !== "undefined") {
  window.addEventListener("online", () => { if (actorId) void refreshLatest(); });
  window.addEventListener("focus", () => { void refreshLatest(); });
  window.addEventListener("pageshow", () => { void refreshLatest(); });
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") void refreshLatest(); });
  window.addEventListener("pagehide", () => { void flush(); });
}
