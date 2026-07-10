import { useGameStore } from "../store/useGameStore";

const DATABASE_NAME = "shieldline-offline-v1";
const DATABASE_VERSION = 1;
const PROJECTION_KEY = "current-game";

interface PendingCommand {
  id?: number;
  path: string;
  method: string;
  body: string;
  createdAt: string;
}

function openDatabase() {
  return new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains("projections")) database.createObjectStore("projections");
      if (!database.objectStoreNames.contains("pendingCommands")) database.createObjectStore("pendingCommands", { keyPath: "id", autoIncrement: true });
      if (!database.objectStoreNames.contains("replayChunks")) database.createObjectStore("replayChunks");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function transact<T>(storeName: string, mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>) {
  const database = await openDatabase();
  return new Promise<T>((resolve, reject) => {
    const transaction = database.transaction(storeName, mode);
    const request = run(transaction.objectStore(storeName));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    transaction.oncomplete = () => database.close();
    transaction.onerror = () => reject(transaction.error);
  });
}

export async function enqueuePendingCommand(command: Omit<PendingCommand, "id" | "createdAt">) {
  if (!("indexedDB" in window)) return;
  await transact("pendingCommands", "readwrite", (store) => store.add({ ...command, createdAt: new Date().toISOString() }));
}

export async function flushPendingCommands(basePath: string) {
  if (!("indexedDB" in window) || !navigator.onLine) return;
  const commands = await transact<PendingCommand[]>("pendingCommands", "readonly", (store) => store.getAll());
  for (const command of commands) {
    const response = await fetch(`${basePath}api${command.path}`, { method: command.method, headers: { "Content-Type": "application/json", "X-Shieldline-Offline-Replay": "1" }, body: command.body }).catch(() => null);
    if (response?.ok && command.id !== undefined) await transact("pendingCommands", "readwrite", (store) => store.delete(command.id!));
    if (!response?.ok) break;
  }
}

export async function initializeOfflinePersistence(basePath: string) {
  if (!("indexedDB" in window)) return;
  let timer = 0;
  const channel = "BroadcastChannel" in window ? new BroadcastChannel("shieldline-game-state") : null;
  useGameStore.subscribe((state) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      const projection = {
        schemaVersion: 1,
        updatedAt: new Date().toISOString(),
        game: state.game,
        activeGameMode: state.activeGameMode,
        operationPhase: state.operationPhase,
        simulationSpeed: state.simulationSpeed,
        simulationSeed: state.simulationSeed,
        simulationRandomCursor: state.simulationRandomCursor,
      };
      void transact("projections", "readwrite", (store) => store.put(projection, PROJECTION_KEY));
      channel?.postMessage({ type: "projection.updated", updatedAt: projection.updatedAt });
    }, 180);
  });
  const flush = () => { void flushPendingCommands(basePath); };
  window.addEventListener("online", flush);
  flush();
}
