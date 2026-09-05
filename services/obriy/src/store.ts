import pg, { type PoolClient } from "pg";
import { randomUUID, createHmac } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { type Config } from "./config.js";
import { Vault, hash, secretToken } from "./security.js";
import {
  type Zone,
  type NormalizedTrack,
  type OfficialAlertEvent,
  type RiskAssessment,
  type AlertState,
} from "./engine/index.js";
export type User = {
  id: string;
  pausedUntil: string | null;
  telegramLinked: boolean;
};
export type Delivery = {
  id: string;
  userId: string;
  chatId: string;
  text: string;
  attempts: number;
  leaseToken: string;
  category: string;
  zoneId: string | null;
  trackId: string | null;
  level?: string;
};
export class Store {
  readonly pool: pg.Pool;
  readonly vault: Vault;
  private leader?: PoolClient;
  constructor(readonly config: Config) {
    this.vault = new Vault(config.OBRIY_ENCRYPTION_KEY);
    this.pool = new pg.Pool(
      config.OBRIY_DATABASE_URL
        ? {
            connectionString: config.OBRIY_DATABASE_URL,
            max: 6,
            connectionTimeoutMillis: 5000,
          }
        : {
            host: config.OBRIY_DB_HOST,
            port: config.OBRIY_DB_PORT,
            database: config.OBRIY_DB_NAME,
            user: config.OBRIY_DB_USER,
            password: config.OBRIY_DB_PASSWORD,
            max: 6,
            connectionTimeoutMillis: 5000,
          },
    );
    this.pool.on("error", () => {
      /* active requests fail closed; no connection details logged */
    });
  }
  async transaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      const value = await fn(c);
      await c.query("COMMIT");
      return value;
    } catch (e) {
      await c.query("ROLLBACK").catch(() => {});
      throw e;
    } finally {
      c.release();
    }
  }
  async migrate() {
    const files = (await readdir(path.resolve("migrations")))
      .filter((n) => /^\d{3}_[a-z_]+\.sql$/.test(n))
      .sort();
    await this.transaction(async (c) => {
      await c.query("SELECT pg_advisory_xact_lock(718031,1)");
      for (const name of files) {
        await c.query(await readFile(path.resolve("migrations", name), "utf8"));
        await c.query(
          "INSERT INTO obriy.schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING",
          [name.slice(0, 3)],
        );
      }
    });
  }
  async acquireLeader(onLost: () => void): Promise<boolean> {
    const c = await this.pool.connect();
    const { rows } = await c.query(
      "SELECT pg_try_advisory_lock(718031,2) AS locked",
    );
    if (!rows[0].locked) {
      c.release();
      return false;
    }
    this.leader = c;
    c.once("error", () => {
      this.leader = undefined;
      c.release(true);
      onLost();
    });
    return true;
  }
  async close() {
    if (this.leader) {
      await this.leader
        .query("SELECT pg_advisory_unlock(718031,2)")
        .catch(() => {});
      this.leader.release();
      this.leader = undefined;
    }
    await this.pool.end();
  }
  async ping() {
    await this.pool.query("SELECT 1");
  }
  async owner(): Promise<string> {
    const { rows } = await this.pool.query(
      "INSERT INTO obriy.users(id,owner) VALUES($1,true) ON CONFLICT(owner) WHERE owner DO UPDATE SET owner=true RETURNING id",
      [randomUUID()],
    );
    return rows[0].id;
  }
  async user(id: string): Promise<User | null> {
    const { rows } = await this.pool.query(
      "SELECT id,paused_until,chat_enc IS NOT NULL AS linked FROM obriy.users WHERE id=$1",
      [id],
    );
    const r = rows[0];
    return r
      ? {
          id: r.id,
          pausedUntil: r.paused_until?.toISOString() ?? null,
          telegramLinked: r.linked,
        }
      : null;
  }
  async session(userId: string): Promise<string> {
    const token = secretToken();
    await this.pool.query(
      "INSERT INTO obriy.sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+$3*interval '1 hour')",
      [hash(token), userId, this.config.OBRIY_SESSION_HOURS],
    );
    return token;
  }
  async sessionUser(token: string): Promise<string | null> {
    const { rows } = await this.pool.query(
      "SELECT s.user_id FROM obriy.sessions s LEFT JOIN obriy.accounts a ON a.user_id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND s.auth_revision IS NOT DISTINCT FROM a.revision",
      [hash(token)],
    );
    return rows[0]?.user_id ?? null;
  }
  async logout(token: string) {
    await this.pool.query("DELETE FROM obriy.sessions WHERE token_hash=$1", [
      hash(token),
    ]);
  }
  async zones(userId?: string): Promise<Zone[]> {
    const { rows } = await this.pool.query(
      "SELECT * FROM obriy.zones" + (userId ? " WHERE user_id=$1" : ""),
      userId ? [userId] : [],
    );
    return rows.map((r) => ({
      ...this.vault.decrypt<Omit<Zone, "id" | "userId">>(
        r.data_enc,
        `zone:${r.id}:${r.user_id}`,
      ),
      id: r.id,
      userId: r.user_id,
      enabled: r.enabled,
    }));
  }
  async saveZone(
    userId: string,
    data: Omit<Zone, "id" | "userId">,
    id?: string,
  ): Promise<Zone | null> {
    return this.transaction(async (c) => {
      await c.query("SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE", [
        userId,
      ]);
      if (id) {
        const existing = await c.query(
          "SELECT id FROM obriy.zones WHERE id=$1 AND user_id=$2 FOR UPDATE",
          [id, userId],
        );
        if (!existing.rowCount) return null;
      } else {
        const count = await c.query(
          "SELECT count(*)::int AS n FROM obriy.zones WHERE user_id=$1",
          [userId],
        );
        if (count.rows[0].n >= 20) throw new Error("Zone limit reached");
      }
      const zid = id ?? randomUUID(),
        encrypted = this.vault.encrypt(data, `zone:${zid}:${userId}`);
      await c.query(
        `INSERT INTO obriy.zones(id,user_id,data_enc,enabled) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET data_enc=$3,enabled=$4,revision=obriy.zones.revision+1,updated_at=now()`,
        [zid, userId, encrypted, data.enabled],
      );
      await c.query("DELETE FROM obriy.alert_state WHERE zone_id=$1", [zid]);
      await c.query(
        "UPDATE obriy.notification_outbox SET status='cancelled' WHERE zone_id=$1 AND status IN ('pending','sending')",
        [zid],
      );
      return { ...data, id: zid, userId };
    });
  }
  async deleteZone(userId: string, id: string) {
    return this.transaction(async (c) => {
      await c.query("SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE", [
        userId,
      ]);
      return Boolean(
        (
          await c.query("DELETE FROM obriy.zones WHERE id=$1 AND user_id=$2", [
            id,
            userId,
          ])
        ).rowCount,
      );
    });
  }
  async deleteUser(id: string) {
    await this.pool.query("DELETE FROM obriy.users WHERE id=$1", [id]);
  }
  async pause(id: string, minutes: number, c?: PoolClient) {
    const run = async (db: PoolClient) => {
      await db.query(
        "UPDATE obriy.users SET paused_until=CASE WHEN $2::int=0 THEN NULL ELSE now()+$2*interval '1 minute' END WHERE id=$1",
        [id, minutes],
      );
      await db.query(
        "UPDATE obriy.notification_outbox SET status='cancelled' WHERE user_id=$1 AND category='risk' AND status IN ('pending','sending')",
        [id],
      );
      await db.query(
        "UPDATE obriy.alert_state a SET data=a.data-'lastNotificationAt'-'lastNotifiedLevel'-'lastNotifiedDistanceBandRank' FROM obriy.zones z WHERE z.id=a.zone_id AND z.user_id=$1",
        [id],
      );
    };
    if (c) await run(c);
    else await this.transaction(run);
  }
  private chatHash(chatId: string) {
    return createHmac("sha256", this.config.OBRIY_ENCRYPTION_KEY)
      .update(`telegram:${chatId}`)
      .digest("hex");
  }
  async chatUser(chatId: string, c?: PoolClient): Promise<string | null> {
    const { rows } = await (c ?? this.pool).query(
      "SELECT id FROM obriy.users WHERE chat_hash=$1",
      [this.chatHash(chatId)],
    );
    return rows[0]?.id ?? null;
  }
  async pairingCode(userId: string) {
    const code = secretToken().slice(0, 24),
      expiresAt = new Date(Date.now() + 600000);
    await this.transaction(async (c) => {
      await c.query("SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE", [
        userId,
      ]);
      await c.query("DELETE FROM obriy.pairing_codes WHERE user_id=$1", [
        userId,
      ]);
      await c.query(
        "INSERT INTO obriy.pairing_codes(code_hash,user_id,expires_at) VALUES($1,$2,$3)",
        [hash(code), userId, expiresAt],
      );
    });
    return { code, expiresAt: expiresAt.toISOString() };
  }
  async linkChat(
    c: PoolClient,
    code: string,
    chatId: string,
  ): Promise<string | null> {
    await c.query("SELECT pg_advisory_xact_lock(hashtextextended($1,718032))", [
      this.chatHash(chatId),
    ]);
    const candidate = await c.query(
      "SELECT user_id FROM obriy.pairing_codes WHERE code_hash=$1 AND expires_at>now()",
      [hash(code)],
    );
    if (!candidate.rowCount) return null;
    await c.query("SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE", [
      candidate.rows[0].user_id,
    ]);
    const existing = await this.chatUser(chatId, c);
    if (existing && existing !== candidate.rows[0].user_id) return null;
    const result = await c.query(
      "DELETE FROM obriy.pairing_codes WHERE code_hash=$1 AND expires_at>now() RETURNING user_id",
      [hash(code)],
    );
    if (!result.rowCount) return null;
    const id = result.rows[0].user_id;
    await c.query(
      "UPDATE obriy.users SET chat_enc=$2,chat_hash=$3 WHERE id=$1",
      [id, this.vault.encrypt(chatId, `chat:${id}`), this.chatHash(chatId)],
    );
    return id;
  }
  async putTrack(track: NormalizedTrack, eventKey: string): Promise<boolean> {
    return this.transaction(async (c) => {
      const event = await c.query(
        "INSERT INTO obriy.source_events(event_key,provider,data) VALUES($1,'neptun',$2) ON CONFLICT DO NOTHING RETURNING event_key",
        [
          eventKey,
          {
            id: track.internalId,
            raw: track.raw ?? {},
            updatedAt: track.updatedAt,
          },
        ],
      );
      if (!event.rowCount) return false;
      const result = await c.query(
        `INSERT INTO obriy.tracks(id,external_id,data,updated_at,status,resolved_at) VALUES($1,$2,$3,$4,$5,CASE WHEN $5='resolved' THEN now() ELSE NULL END) ON CONFLICT(id) DO UPDATE SET data=$3,updated_at=$4,status=$5,received_at=now(),resolved_at=CASE WHEN $5='resolved' THEN now() ELSE NULL END WHERE obriy.tracks.updated_at<$4 RETURNING id`,
        [
          track.internalId,
          track.source.externalTrackId,
          { ...track, raw: undefined },
          track.updatedAt,
          track.status,
        ],
      );
      if (
        result.rowCount &&
        !track.position.areaOnly &&
        track.position.lat !== undefined
      )
        await c.query(
          "INSERT INTO obriy.track_points(track_id,observed_at,data) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
          [track.internalId, track.updatedAt, track.position],
        );
      return Boolean(result.rowCount);
    });
  }
  async resolveTrack(externalId: string, at: Date) {
    const { rows } = await this.pool.query(
      "UPDATE obriy.tracks SET status='resolved',resolved_at=$2,updated_at=$2, data=jsonb_set(jsonb_set(data,'{status}','\"resolved\"'),'{updatedAt}',to_jsonb($2::timestamptz)) WHERE external_id=$1 AND updated_at<=$2 AND status<>'resolved' RETURNING id",
      [externalId, at],
    );
    return rows[0]?.id as string | undefined;
  }
  async reconcile(ids: string[], at: Date) {
    const { rows } = await this.pool.query(
      "SELECT external_id FROM obriy.tracks WHERE status<>'resolved' AND updated_at<=$1 AND NOT(external_id=ANY($2::text[]))",
      [at, ids],
    );
    for (const row of rows) await this.resolveTrack(row.external_id, at);
  }
  async tracks(): Promise<NormalizedTrack[]> {
    const { rows } = await this.pool.query(
      "SELECT data,status,resolved_at FROM obriy.tracks WHERE status<>'resolved' OR resolved_at>now()-interval '10 minutes'",
    );
    return rows.map((r) => ({ ...r.data, status: r.status }));
  }
  async official(provider: string, events: OfficialAlertEvent[]) {
    await this.transaction(async (c) => {
      await c.query(
        "UPDATE obriy.official_alerts SET active=false,received_at=now() WHERE provider=$1",
        [provider],
      );
      for (const event of events)
        await c.query(
          "INSERT INTO obriy.official_alerts(provider,external_id,data,active,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(provider,external_id) DO UPDATE SET data=$3,active=$4,updated_at=$5,received_at=now()",
          [provider, event.externalId, event, event.active, event.updatedAt],
        );
    });
  }
  async activeAlerts(): Promise<OfficialAlertEvent[]> {
    const { rows } = await this.pool.query(
      "SELECT data FROM obriy.official_alerts WHERE active AND received_at>now()-interval '60 seconds'",
    );
    return rows.map((r) => r.data);
  }
  async refreshOfficial(provider: string) {
    await this.pool.query(
      "UPDATE obriy.official_alerts SET received_at=now() WHERE provider=$1",
      [provider],
    );
  }
  async recordAssessment(
    zone: Zone,
    track: NormalizedTrack,
    assessment: RiskAssessment,
    calculate: (old: AlertState | null) => {
      state: AlertState;
      notify: boolean;
    },
    text: (level: AlertState["currentLevel"]) => string,
    eventKey: string,
  ) {
    await this.transaction(async (c) => {
      const user = await c.query(
        "SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE",
        [zone.userId],
      );
      if (!user.rowCount) return;
      const z = await c.query(
        "SELECT enabled,updated_at,data_enc FROM obriy.zones WHERE id=$1 FOR UPDATE",
        [zone.id],
      );
      if (!z.rowCount || !z.rows[0].enabled) return;
      const currentZone = this.vault.decrypt<Omit<Zone, "id" | "userId">>(
        z.rows[0].data_enc,
        `zone:${zone.id}:${zone.userId}`,
      );
      if (
        currentZone.lat !== zone.lat ||
        currentZone.lon !== zone.lon ||
        currentZone.radiusKm !== zone.radiusKm ||
        currentZone.oblast !== zone.oblast ||
        currentZone.regionUid !== zone.regionUid
      )
        return;
      const { rows } = await c.query(
        "SELECT data FROM obriy.alert_state WHERE zone_id=$1 AND track_id=$2",
        [zone.id, track.internalId],
      );
      const previous: AlertState | null = rows[0]?.data ?? null,
        next = calculate(previous);
      // A queued notification is not yet an actual delivered warning.
      next.state.hadHighLevelNotification =
        previous?.currentLevel === "RESOLVED" && !assessment.resolved
          ? false
          : (previous?.hadHighLevelNotification ?? false);
      if (
        !assessment.escalationAllowed ||
        assessment.level === "INFO" ||
        assessment.level === "WATCH"
      )
        await c.query(
          "UPDATE obriy.notification_outbox SET status='cancelled' WHERE zone_id=$1 AND track_id=$2 AND category='risk' AND status IN ('pending','sending')",
          [zone.id, track.internalId],
        );
      if (next.notify) {
        const inserted = await this.enqueue(
          c,
          zone.userId,
          text(next.state.currentLevel),
          `risk:${zone.id}:${track.internalId}:${eventKey}:${next.state.currentLevel}`,
          {
            zoneId: zone.id,
            trackId: track.internalId,
            level: next.state.currentLevel,
          },
        );
        if (!inserted) {
          next.state.lastNotificationAt = previous?.lastNotificationAt;
          next.state.lastNotifiedLevel = previous?.lastNotifiedLevel;
          next.state.lastNotifiedDistanceBandRank =
            previous?.lastNotifiedDistanceBandRank;
        }
      }
      const regionRelevant = Boolean(
        zone.oblast &&
        track.geography.region &&
        zone.oblast.toLocaleLowerCase("uk") ===
          track.geography.region.toLocaleLowerCase("uk"),
      );
      const relevant =
        assessment.geometry.corridorIntersects ||
        (assessment.geometry.currentDistanceKm !== undefined &&
          assessment.geometry.currentDistanceKm <= zone.radiusKm + 100) ||
        regionRelevant ||
        Boolean(next.state.hadHighLevelNotification);
      const enc = this.vault.encrypt(
        {
          ...assessment,
          relevant,
          level: next.state.currentLevel,
          threatType: track.threat.type,
          upstreamUpdatedAt: track.updatedAt,
        },
        `assessment:${zone.id}`,
      );
      await c.query(
        "INSERT INTO obriy.alert_state(zone_id,track_id,data,assessment_enc) VALUES($1,$2,$3,$4) ON CONFLICT(zone_id,track_id) DO UPDATE SET data=$3,assessment_enc=$4,updated_at=now()",
        [zone.id, track.internalId, next.state, enc],
      );
      await c.query(
        "INSERT INTO obriy.risk_assessments(zone_id,track_id,data_enc,engine_version) VALUES($1,$2,$3,$4)",
        [zone.id, track.internalId, enc, assessment.engineConfigVersion],
      );
    });
  }
  async assessments(userId: string) {
    const { rows } = await this.pool.query(
      "SELECT a.assessment_enc,a.zone_id FROM obriy.alert_state a JOIN obriy.zones z ON z.id=a.zone_id WHERE z.user_id=$1 AND z.enabled ORDER BY a.updated_at DESC LIMIT 200",
      [userId],
    );
    return rows
      .map((r) =>
        this.vault.decrypt<RiskAssessment & { relevant?: boolean }>(
          r.assessment_enc,
          `assessment:${r.zone_id}`,
        ),
      )
      .filter((a) => a.relevant !== false)
      .map(({ geometry, ...a }) => ({
        ...a,
        geometry: {
          distanceBand: geometry.distanceBand,
          corridorIntersects: geometry.corridorIntersects,
        },
      }));
  }
  async enqueue(
    c: PoolClient,
    userId: string,
    text: string,
    dedupe: string,
    refs?: { zoneId: string; trackId: string; level?: string },
    ttl = 120,
  ) {
    const id = randomUUID();
    const result = await c.query(
      `INSERT INTO obriy.notification_outbox(id,dedupe_key,user_id,zone_id,track_id,payload_enc,category,expires_at) SELECT $1,$2,id,$4,$5,$6,$7,now()+$8*interval '1 second' FROM obriy.users WHERE id=$3 AND chat_enc IS NOT NULL AND ($7='command' OR paused_until IS NULL OR paused_until<=now()) ON CONFLICT(dedupe_key) DO NOTHING RETURNING id`,
      [
        id,
        dedupe,
        userId,
        refs?.zoneId ?? null,
        refs?.trackId ?? null,
        this.vault.encrypt({ text, level: refs?.level }, `outbox:${id}`),
        refs ? "risk" : "command",
        ttl,
      ],
    );
    return Boolean(result.rowCount);
  }
  async claim(): Promise<Delivery | null> {
    return this.transaction(async (c) => {
      // Every personalized mutation locks user, then zone, then its child rows.
      // Select the user first so claiming cannot deadlock a concurrent zone edit.
      const users = await c.query(
        `SELECT u.id FROM obriy.users u WHERE u.chat_enc IS NOT NULL AND (u.last_delivery_at IS NULL OR u.last_delivery_at<now()-interval '1100 milliseconds') AND EXISTS (SELECT 1 FROM obriy.notification_outbox o WHERE o.user_id=u.id AND (o.status='pending' OR(o.status='sending' AND o.lease_until<now())) AND o.retry_at<=now() AND o.expires_at>now() AND(o.category='command' OR u.paused_until IS NULL OR u.paused_until<=now())) ORDER BY u.last_delivery_at NULLS FIRST FOR UPDATE OF u SKIP LOCKED LIMIT 1`,
      );
      if (!users.rows[0]) return null;
      const { rows } = await c.query(
        `SELECT o.*,u.chat_enc FROM obriy.notification_outbox o JOIN obriy.users u ON u.id=o.user_id WHERE o.user_id=$1 AND (o.status='pending' OR(o.status='sending' AND o.lease_until<now())) AND o.retry_at<=now() AND o.expires_at>now() AND(o.category='command' OR u.paused_until IS NULL OR u.paused_until<=now()) ORDER BY o.created_at FOR UPDATE OF o SKIP LOCKED LIMIT 1`,
        [users.rows[0].id],
      );
      if (!rows[0]) return null;
      const r = rows[0],
        leaseToken = randomUUID();
      await c.query(
        "UPDATE obriy.notification_outbox SET status='sending',attempts=attempts+1,lease_until=now()+interval '45 seconds',lease_token=$2 WHERE id=$1",
        [r.id, leaseToken],
      );
      await c.query(
        "UPDATE obriy.users SET last_delivery_at=now() WHERE id=$1",
        [r.user_id],
      );
      return {
        id: r.id,
        userId: r.user_id,
        chatId: this.vault.decrypt<string>(r.chat_enc, `chat:${r.user_id}`),
        text: this.vault.decrypt<{ text: string }>(
          r.payload_enc,
          `outbox:${r.id}`,
        ).text,
        attempts: r.attempts + 1,
        leaseToken,
        category: r.category,
        zoneId: r.zone_id,
        trackId: r.track_id,
        level: this.vault.decrypt<{ level?: string }>(
          r.payload_enc,
          `outbox:${r.id}`,
        ).level,
      };
    });
  }
  async deliverable(d: Delivery) {
    const { rows } = await this.pool.query(
      `SELECT 1 FROM obriy.notification_outbox o JOIN obriy.users u ON u.id=o.user_id LEFT JOIN obriy.zones z ON z.id=o.zone_id LEFT JOIN obriy.tracks t ON t.id=o.track_id WHERE o.id=$1 AND o.lease_token=$2 AND u.chat_hash=$4 AND o.status='sending' AND o.expires_at>now() AND(o.category='command' OR ((u.paused_until IS NULL OR u.paused_until<=now()) AND z.enabled AND (($3='RESOLVED' AND t.status='resolved') OR ($3 IS DISTINCT FROM 'RESOLVED' AND t.status='active' AND t.data->>'advisory'='false' AND t.data#>>'{position,areaOnly}'='false' AND t.data#>>'{motion,speedKmh}' IS NOT NULL AND t.data#>>'{motion,confirmedAt}' IS NOT NULL AND (t.data->>'observedAt')::timestamptz>now()-interval '600 seconds'))))`,
      [d.id, d.leaseToken, d.level ?? null, this.chatHash(d.chatId)],
    );
    return Boolean(rows.length);
  }
  async finish(
    d: Delivery,
    outcome: "sent" | "retry" | "dead" | "cancelled",
    retrySeconds = 0,
    code = "",
  ) {
    await this.transaction(async (c) => {
      const user = await c.query(
        "SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE",
        [d.userId],
      );
      if (!user.rowCount) return;
      if (d.zoneId) {
        const zone = await c.query(
          "SELECT id FROM obriy.zones WHERE id=$1 FOR UPDATE",
          [d.zoneId],
        );
        if (!zone.rowCount) return;
      }
      const finished = await c.query(
        "UPDATE obriy.notification_outbox SET status=$3,retry_at=now()+$4*interval '1 second',lease_until=NULL,last_error_code=$5 WHERE id=$1 AND lease_token=$2 AND status='sending'",
        [
          d.id,
          d.leaseToken,
          outcome === "retry" ? "pending" : outcome,
          retrySeconds,
          code,
        ],
      );
      if (!finished.rowCount) return;
      if (
        outcome === "sent" &&
        d.zoneId &&
        d.trackId &&
        ["WARNING", "HIGH"].includes(d.level ?? "")
      )
        await c.query(
          "UPDATE obriy.alert_state SET data=jsonb_set(data,'{hadHighLevelNotification}','true') WHERE zone_id=$1 AND track_id=$2",
          [d.zoneId, d.trackId],
        );
      if (outcome === "sent")
        await c.query(
          "INSERT INTO obriy.notifications(id,user_id,outbox_id,status) SELECT $1,id,$3,'sent' FROM obriy.users WHERE id=$2 ON CONFLICT DO NOTHING",
          [d.id, d.userId, d.id],
        );
    });
  }
  async getRuntime<T>(key: string): Promise<T | null> {
    const { rows } = await this.pool.query(
      "SELECT data FROM obriy.runtime_state WHERE key=$1",
      [key],
    );
    return rows[0]?.data ?? null;
  }
  async setRuntime(key: string, data: unknown) {
    await this.pool.query(
      "INSERT INTO obriy.runtime_state(key,data) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET data=$2,updated_at=now()",
      [key, data],
    );
  }
  async counts() {
    const { rows } = await this.pool.query(
      "SELECT (SELECT count(*)::int FROM obriy.tracks WHERE status='active') AS tracks,(SELECT count(*)::int FROM obriy.notification_outbox WHERE status='pending') AS pending,(SELECT count(*)::int FROM obriy.notification_outbox WHERE status='dead') AS dead",
    );
    return rows[0] as { tracks: number; pending: number; dead: number };
  }
  async cleanup() {
    const days = this.config.OBRIY_RETENTION_DAYS;
    await this.transaction(async (c) => {
      await c.query("SELECT id FROM obriy.users ORDER BY id FOR UPDATE");
      await c.query(
        "UPDATE obriy.notification_outbox SET status='expired' WHERE status IN ('pending','sending') AND expires_at<=now()",
      );
      await c.query("DELETE FROM obriy.sessions WHERE expires_at<now()");
      await c.query("DELETE FROM obriy.access_gates WHERE expires_at<now()");
      await c.query(
        "DELETE FROM obriy.login_attempts WHERE attempted_at<now()-interval '5 minutes'",
      );
      await c.query("DELETE FROM obriy.pairing_codes WHERE expires_at<now()");
      await c.query(
        "DELETE FROM obriy.source_events WHERE created_at<now()-$1*interval '1 hour'",
        [this.config.OBRIY_RAW_RETENTION_HOURS],
      );
      await c.query(
        "DELETE FROM obriy.track_points WHERE observed_at<now()-interval '7 days'",
      );
      await c.query(
        "DELETE FROM obriy.tracks WHERE updated_at<now()-interval '7 days'",
      );
      await c.query(
        "DELETE FROM obriy.official_alerts WHERE received_at<now()-$1*interval '1 day'",
        [days],
      );
      for (const table of [
        "risk_assessments",
        "notification_outbox",
        "notifications",
        "audit_events",
      ])
        await c.query(
          `DELETE FROM obriy.${table} WHERE created_at<now()-$1*interval '1 day'`,
          [days],
        );
      await c.query(
        "DELETE FROM obriy.telegram_updates WHERE processed_at<now()-interval '7 days'",
      );
    });
  }
}
