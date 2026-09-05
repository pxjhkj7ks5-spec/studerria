import { EventEmitter } from "node:events";
import { WebSocketServer } from "ws";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  AlertsCollector,
  DisabledSecondarySource,
  NeptunCollector,
} from "../src/ingestion/index.js";
import { retryAfterMs, sourceDate } from "../src/ingestion/http.js";

class FakeSocket extends EventEmitter {
  closed = false;
  terminate(): void {
    if (this.closed) return;
    this.closed = true;
    this.emit("close");
  }
  frame(type: string, data?: unknown, ts = new Date().toISOString()): void {
    this.emit(
      "message",
      Buffer.from(
        JSON.stringify({ type, ts, ...(data === undefined ? {} : { data }) }),
      ),
      false,
    );
  }
}

const collectors: Array<{ stop(): Promise<void> }> = [];
const jsonResponse = (
  data: unknown,
  headers?: Record<string, string>,
): Response =>
  new Response(JSON.stringify(data), {
    status: 200,
    headers: { "Content-Type": "application/json", ...headers },
  });
const flush = () => vi.advanceTimersByTimeAsync(0);

function makeNeptun(
  overrides: Partial<ConstructorParameters<typeof NeptunCollector>[0]> = {},
) {
  const sockets: FakeSocket[] = [];
  const callbacks = {
    onSnapshot: vi.fn(async (_raw: unknown[], _at: Date) => {}),
    onUpsert: vi.fn(async (_raw: unknown, _at: Date) => {}),
    onRemove: vi.fn(async (_id: string, _at: Date) => {}),
    onAlerts: vi.fn(async (_raw: unknown, _at: Date) => {}),
    onError: vi.fn(),
  };
  const fetcher = vi.fn(async () =>
    jsonResponse({ serverTime: new Date().toISOString(), threats: [] }),
  );
  const collector = new NeptunCollector({
    wsUrl: "wss://source.example/stream",
    restUrl: "https://source.example/threats",
    pollMs: 5000,
    heartbeatMs: 60_000,
    random: () => 0,
    socketFactory: () => {
      const socket = new FakeSocket();
      sockets.push(socket);
      return socket;
    },
    fetch: fetcher,
    ...callbacks,
    ...overrides,
  });
  collectors.push(collector);
  collector.start();
  sockets[0]?.emit("open");
  return { collector, sockets, fetcher, ...callbacks };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-09-05T12:00:00.000Z"));
});
afterEach(async () => {
  for (const collector of collectors.splice(0)) await collector.stop();
  vi.useRealTimers();
});

describe("NEPTUN contracts and recovery", () => {
  it("connects over the real WebSocket transport to a local synthetic protocol fixture", async () => {
    vi.useRealTimers();
    const server = new WebSocketServer({ port: 0, host: "127.0.0.1" });
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("No fixture address");
    server.on("connection", (socket) => {
      const ts = new Date().toISOString();
      socket.send(
        JSON.stringify({ type: "snapshot", ts, data: { threats: [] } }),
      );
      socket.send(JSON.stringify({ type: "heartbeat", ts }));
      socket.send(
        JSON.stringify({ type: "upsert", ts, data: { id: "synthetic-only" } }),
      );
    });
    const onSnapshot = vi.fn(async () => {}),
      onUpsert = vi.fn(async () => {});
    const collector = new NeptunCollector({
      wsUrl: `ws://127.0.0.1:${address.port}`,
      restUrl: "https://unused.example/threats",
      pollMs: 5000,
      heartbeatMs: 60_000,
      onSnapshot,
      onUpsert,
      onRemove: async () => {},
      onAlerts: async () => {},
    });
    collectors.push(collector);
    try {
      collector.start();
      await vi.waitFor(() => expect(onUpsert).toHaveBeenCalledOnce(), {
        timeout: 2000,
        interval: 10,
      });
      expect(onSnapshot).toHaveBeenCalledOnce();
      expect(collector.health().state).toBe("live");
    } finally {
      await collector.stop();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("accepts all observed envelopes including heartbeat without data; never fetches while synchronized", async () => {
    const result = makeNeptun();
    const socket = result.sockets[0];
    socket.frame("snapshot", { threats: [{ id: "synthetic-a" }] });
    socket.frame("heartbeat");
    socket.frame("upsert", { id: "synthetic-b" });
    socket.frame("alerts", {
      version: 1,
      updatedAt: new Date().toISOString(),
      raions: [],
      oblasts: [],
    });
    socket.frame("remove", { id: "synthetic-a" });
    await flush();
    expect(result.onSnapshot).toHaveBeenCalledOnce();
    expect(result.onUpsert).toHaveBeenCalledOnce();
    expect(result.onRemove).toHaveBeenCalledWith(
      "synthetic-a",
      expect.any(Date),
    );
    expect(result.onAlerts).toHaveBeenCalledOnce();
    expect(result.onError).not.toHaveBeenCalled();
    expect(result.collector.health().state).toBe("live");
    expect(result.collector.health().transport).toBe("websocket");
    await vi.advanceTimersByTimeAsync(15_000);
    expect(result.fetcher).not.toHaveBeenCalled();
  });

  it("deduplicates exact updates and prevents older remove or tombstoned upsert from changing state", async () => {
    const result = makeNeptun();
    const socket = result.sockets[0];
    socket.frame("snapshot", { threats: [] });
    await flush();
    await vi.advanceTimersByTimeAsync(2000);
    const time = new Date().toISOString();
    socket.frame("upsert", { id: "synthetic-a", newField: true }, time);
    socket.frame("upsert", { id: "synthetic-a", newField: true }, time);
    socket.frame("remove", { id: "synthetic-a" }, "2026-09-05T12:00:01.000Z");
    await flush();
    expect(result.onUpsert).toHaveBeenCalledOnce();
    expect(result.onRemove).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1000);
    socket.frame("remove", { id: "synthetic-a" });
    socket.frame("remove", { id: "synthetic-a" });
    socket.frame("upsert", { id: "synthetic-a" });
    await flush();
    expect(result.onRemove).toHaveBeenCalledOnce();
    expect(result.onUpsert).toHaveBeenCalledOnce();
  });

  it("reconnects once and replaces current state from a fresh snapshot before applying deltas", async () => {
    const state = new Set<string>();
    const result = makeNeptun({
      onSnapshot: async (raw) => {
        state.clear();
        for (const item of raw) state.add((item as { id: string }).id);
      },
      onUpsert: async (raw) => {
        state.add((raw as { id: string }).id);
      },
    });
    result.sockets[0].frame("snapshot", { threats: [{ id: "old" }] });
    await flush();
    result.sockets[0].terminate();
    await vi.advanceTimersByTimeAsync(1000);
    expect(result.sockets).toHaveLength(2);
    result.collector.start();
    expect(result.sockets).toHaveLength(2);
    result.sockets[1].emit("open");
    result.sockets[1].frame("upsert", { id: "before-snapshot" });
    await flush();
    expect(state).toEqual(new Set(["old"]));
    result.sockets[1].frame("snapshot", { threats: [{ id: "new" }] });
    result.sockets[1].frame("upsert", { id: "after-snapshot" });
    await flush();
    expect(state).toEqual(new Set(["new", "after-snapshot"]));
    expect(result.collector.health().state).toBe("live");
  });

  it("ignores malformed, future, oversized and unknown envelopes without disclosing raw input", async () => {
    const result = makeNeptun({ maxFrameBytes: 1024 });
    const socket = result.sockets[0];
    socket.emit(
      "message",
      Buffer.from("{ hostile-token: very-sensitive "),
      false,
    );
    socket.frame("snapshot", { threats: {} });
    socket.frame("upsert", { id: "fake" }, "2099-01-01T00:00:00Z");
    socket.frame("new-event", { sensitive: "never-log" });
    socket.frame("snapshot", {
      threats: [{ id: "x", text: "a".repeat(1100) }],
    });
    await flush();
    expect(result.onSnapshot).not.toHaveBeenCalled();
    expect(result.onUpsert).not.toHaveBeenCalled();
    expect(result.onError.mock.calls.flat()).toEqual(
      expect.arrayContaining([
        "neptun_invalid_json",
        "neptun_invalid_data",
        "neptun_invalid_timestamp",
        "neptun_unknown_event",
        "neptun_frame_too_large",
      ]),
    );
    expect(JSON.stringify(result.onError.mock.calls)).not.toContain(
      "hostile-token",
    );
    expect(JSON.stringify(result.onError.mock.calls)).not.toContain(
      "never-log",
    );
    expect(socket.closed).toBe(true);
  });

  it("uses watchdog even if a stream sends heartbeats but never supplies a snapshot", async () => {
    const result = makeNeptun({ heartbeatMs: 100 });
    for (let i = 0; i < 4; i++) {
      result.sockets[0].frame("heartbeat");
      await vi.advanceTimersByTimeAsync(40);
    }
    expect(result.sockets[0].closed).toBe(true);
    expect(result.onError).toHaveBeenCalledWith("neptun_heartbeat_timeout");
  });

  it("heartbeat refreshes synchronized threat freshness and only current official state", async () => {
    const onHeartbeat = vi.fn(async () => {});
    const result = makeNeptun({ onHeartbeat });
    const socket = result.sockets[0];
    socket.frame("heartbeat");
    await flush();
    expect(result.collector.health().lastSuccessAt).toBeUndefined();
    socket.frame("snapshot", { threats: [] });
    await flush();
    for (let i = 0; i < 4; i++) {
      await vi.advanceTimersByTimeAsync(30_000);
      socket.frame("heartbeat");
      await flush();
      expect(result.collector.health().lastSuccessAt).toBe(
        new Date().toISOString(),
      );
    }
    expect(onHeartbeat).not.toHaveBeenCalled();
    socket.frame("alerts", { raions: [], oblasts: [] });
    socket.frame("heartbeat");
    await flush();
    expect(onHeartbeat).toHaveBeenCalledOnce();
    expect(result.collector.health().state).toBe("live");
    expect(result.fetcher).not.toHaveBeenCalled();
    socket.terminate();
    await vi.advanceTimersByTimeAsync(1000);
    result.sockets[1].frame("snapshot", { threats: [] });
    result.sockets[1].frame("heartbeat");
    await flush();
    expect(onHeartbeat).toHaveBeenCalledOnce();
  });

  it("does not overwrite newer official alert state with an out-of-order frame", async () => {
    const result = makeNeptun();
    result.sockets[0].frame("alerts", { raions: [], oblasts: [] });
    await flush();
    result.sockets[0].frame(
      "alerts",
      { raions: [{ id: "stale" }], oblasts: [] },
      "2026-09-05T11:59:59.000Z",
    );
    await flush();
    expect(result.onAlerts).toHaveBeenCalledOnce();
    expect(result.onError).toHaveBeenCalledWith("neptun_old_alerts");
  });

  it("bounds pending work, drops obsolete deltas after overflow and resynchronizes", async () => {
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const result = makeNeptun({
      maxQueueEntries: 1,
      onSnapshot: async () => blocked,
    });
    const socket = result.sockets[0];
    socket.frame("snapshot", { threats: [] });
    socket.frame("upsert", { id: "queued" });
    socket.frame("upsert", { id: "overflow" });
    expect(result.onError).toHaveBeenCalledWith("neptun_queue_overflow");
    release();
    await flush();
    expect(result.onUpsert).not.toHaveBeenCalled();
    expect(result.collector.health().state).toBe("degraded");
    await vi.advanceTimersByTimeAsync(1000);
    expect(result.sockets).toHaveLength(2);
  });

  it("fallback obeys the five-second floor and never overlaps requests", async () => {
    let release!: (value: Response) => void;
    const slowFetch = vi.fn(
      () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    );
    const result = makeNeptun({ pollMs: 1, fetch: slowFetch });
    await vi.advanceTimersByTimeAsync(4999);
    expect(slowFetch).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(slowFetch).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(20_000);
    expect(slowFetch).toHaveBeenCalledOnce();
    release(
      jsonResponse({ serverTime: new Date().toISOString(), threats: [] }),
    );
    await flush();
    expect(result.collector.health().transport).toBe("rest");
    await vi.advanceTimersByTimeAsync(4999);
    expect(slowFetch).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    expect(slowFetch).toHaveBeenCalledTimes(2);
    release(
      jsonResponse({ serverTime: new Date().toISOString(), threats: [] }),
    );
    await flush();
  });

  it("a delayed REST snapshot cannot remove newer WebSocket state", async () => {
    let release!: (value: Response) => void;
    const result = makeNeptun({
      fetch: async () =>
        new Promise<Response>((resolve) => {
          release = resolve;
        }),
    });
    await vi.advanceTimersByTimeAsync(5000);
    const oldSnapshotTime = new Date().toISOString();
    await vi.advanceTimersByTimeAsync(1000);
    result.sockets[0].frame("snapshot", { threats: [{ id: "new" }] });
    await flush();
    release(jsonResponse({ serverTime: oldSnapshotTime, threats: [] }));
    await flush();
    expect(result.onSnapshot).toHaveBeenCalledOnce();
    expect(result.onSnapshot.mock.calls[0][0]).toEqual([{ id: "new" }]);
    expect(result.onError).toHaveBeenCalledWith("neptun_old_snapshot");
  });

  it("fails closed after persistence callback errors, then recovers from a new snapshot", async () => {
    const save = vi
      .fn()
      .mockRejectedValueOnce(new Error("password-secret"))
      .mockResolvedValue(undefined);
    const result = makeNeptun({ onSnapshot: save });
    result.sockets[0].frame("snapshot", { threats: [] });
    await flush();
    expect(result.onError).toHaveBeenCalledWith("neptun_callback_failed");
    expect(result.sockets[0].closed).toBe(true);
    expect(JSON.stringify(result.onError.mock.calls)).not.toContain(
      "password-secret",
    );
    await vi.advanceTimersByTimeAsync(1000);
    result.sockets[1].frame("snapshot", { threats: [] });
    await flush();
    expect(result.collector.health().state).toBe("live");
  });

  it("rejects oversized streaming REST bodies and backs off HTTP 429", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          serverTime: new Date().toISOString(),
          threats: [{ text: "x".repeat(2000) }],
        }),
      )
      .mockResolvedValueOnce(
        new Response(null, { status: 429, headers: { "Retry-After": "120" } }),
      )
      .mockImplementation(async () =>
        jsonResponse({ serverTime: new Date().toISOString(), threats: [] }),
      );
    const result = makeNeptun({ fetch: fetcher, maxFrameBytes: 1024 });
    await vi.advanceTimersByTimeAsync(5000);
    expect(result.onError).toHaveBeenCalledWith("neptun_body_too_large");
    await vi.advanceTimersByTimeAsync(5000);
    expect(result.onError).toHaveBeenCalledWith("neptun_http_429");
    await vi.advanceTimersByTimeAsync(119_999);
    expect(fetcher).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetcher).toHaveBeenCalledTimes(3);
  });
});

describe("official alerts adapter", () => {
  function makeAlerts(
    fetcher: ConstructorParameters<typeof AlertsCollector>[0]["fetch"],
    token = "secret-test-token",
  ) {
    const onAlerts = vi.fn(async (_raw: unknown, _at: Date) => {});
    const onError = vi.fn();
    const collector = new AlertsCollector({
      url: "https://alerts.example/active.json",
      token,
      pollMs: 1,
      fetch: fetcher,
      onAlerts,
      onError,
    });
    collectors.push(collector);
    collector.start();
    return { collector, onAlerts, onError };
  }

  it("stays disabled without a token", async () => {
    const fetcher = vi.fn();
    const result = makeAlerts(fetcher, "");
    await vi.advanceTimersByTimeAsync(120_000);
    expect(fetcher).not.toHaveBeenCalled();
    expect(result.collector.health()).toEqual({ state: "disabled" });
  });

  it("keeps bearer server-side and conditional 304 refreshes unchanged context", async () => {
    const payload = {
      alerts: [{ id: 10, location_uid: "14", alert_type: "air_raid" }],
    };
    const modified = "Sat, 05 Sep 2026 11:59:00 GMT";
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse(payload, { "Last-Modified": modified }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 304 }));
    const result = makeAlerts(fetcher);
    await flush();
    expect(fetcher.mock.calls[0][0]).toBe("https://alerts.example/active.json");
    expect(fetcher.mock.calls[0][1].headers.Authorization).toBe(
      "Bearer secret-test-token",
    );
    await vi.advanceTimersByTimeAsync(11_999);
    expect(fetcher).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    expect(fetcher.mock.calls[1][1].headers["If-Modified-Since"]).toBe(
      modified,
    );
    expect(fetcher.mock.calls[1][1].redirect).toBe("error");
    expect(result.onAlerts).toHaveBeenCalledTimes(2);
    expect(result.onAlerts.mock.calls[1][0]).toEqual(payload);
    expect(result.onAlerts.mock.calls[1][1].getTime()).toBe(Date.now());
    expect(result.collector.health().lastSuccessAt).toBe(
      new Date().toISOString(),
    );
  });

  it.each([401, 403])(
    "backs off authorization HTTP %s for five minutes",
    async (status) => {
      const fetcher = vi.fn().mockResolvedValue(new Response(null, { status }));
      const result = makeAlerts(fetcher);
      await flush();
      expect(result.collector.health().state).toBe("error");
      expect(result.onError).toHaveBeenCalledWith(`alerts_http_${status}`);
      await vi.advanceTimersByTimeAsync(299_999);
      expect(fetcher).toHaveBeenCalledOnce();
      await vi.advanceTimersByTimeAsync(1);
      expect(fetcher).toHaveBeenCalledTimes(2);
    },
  );

  it("obeys HTTP-date Retry-After and never marks unknown 304 as healthy", async () => {
    const retryAt = new Date(Date.now() + 120_000).toUTCString();
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(null, {
          status: 429,
          headers: { "Retry-After": retryAt },
        }),
      )
      .mockResolvedValueOnce(new Response(null, { status: 304 }));
    const result = makeAlerts(fetcher);
    await flush();
    await vi.advanceTimersByTimeAsync(119_999);
    expect(fetcher).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(result.onAlerts).not.toHaveBeenCalled();
    expect(result.onError).toHaveBeenCalledWith("alerts_304_without_snapshot");
    expect(result.collector.health().state).toBe("degraded");
  });

  it("handles malformed schema/JSON and temporary failures with only safe error codes", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({ error: "token-secret" }))
      .mockResolvedValueOnce(
        new Response("{ invalid-sensitive-body", { status: 200 }),
      )
      .mockRejectedValueOnce(new Error("network token-secret"))
      .mockResolvedValueOnce(jsonResponse({ alerts: [] }));
    const result = makeAlerts(fetcher);
    await flush();
    await vi.advanceTimersByTimeAsync(12_000);
    await vi.advanceTimersByTimeAsync(24_000);
    await vi.advanceTimersByTimeAsync(48_000);
    expect(result.onAlerts).toHaveBeenCalledOnce();
    expect(result.collector.health().state).toBe("live");
    expect(result.onError.mock.calls.flat()).toEqual([
      "alerts_invalid_snapshot",
      "alerts_invalid_json",
      "alerts_fetch_failed",
    ]);
    expect(JSON.stringify(result.onError.mock.calls)).not.toContain("secret");
  });

  it("stopping aborts in-flight fetch and schedules no later work", async () => {
    let signal: AbortSignal | undefined;
    const fetcher = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          signal = init?.signal as AbortSignal;
          signal.addEventListener("abort", () => reject(new Error("aborted")), {
            once: true,
          });
        }),
    );
    const result = makeAlerts(fetcher);
    await flush();
    await result.collector.stop();
    expect(signal?.aborted).toBe(true);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(fetcher).toHaveBeenCalledOnce();
    expect(result.onError).not.toHaveBeenCalled();
  });
});

describe("shared source guards", () => {
  it("normalizes Retry-After safely, including overflow and malformed headers", () => {
    expect(retryAfterMs("5", Date.now(), 12_000)).toBe(12_000);
    expect(retryAfterMs("120", Date.now(), 12_000)).toBe(120_000);
    expect(retryAfterMs("99999999999", Date.now(), 12_000)).toBe(2_147_483_647);
    expect(retryAfterMs("nonsense", Date.now(), 12_000)).toBe(12_000);
  });
  it("rejects invalid/future timestamps and leaves secondary sources explicitly disabled", async () => {
    expect(sourceDate("not-a-date", Date.now())).toBeNull();
    expect(sourceDate("1960-01-01T00:00:00Z", Date.now())).toBeNull();
    expect(sourceDate("2099-01-01T00:00:00Z", Date.now())).toBeNull();
    expect(sourceDate(new Date().toISOString(), Date.now())).toEqual(
      new Date(),
    );
    const secondary = new DisabledSecondarySource();
    await secondary.start(new AbortController().signal);
    expect(secondary.id).toBe("airsigma");
    expect(secondary.health()).toEqual({ state: "disabled" });
  });
});
