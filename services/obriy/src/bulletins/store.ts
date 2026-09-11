import { randomUUID } from "node:crypto";
import type { Store } from "../store.js";
import type { Zone } from "../engine/types.js";
import { hash } from "../security.js";
import { AREAS, matchingAreas } from "./areas.js";
import { zoneAreas, areaLabel } from "./settlements.js";
import { parseBulletin } from "./parser.js";
import {
  CHANNELS,
  type Bulletin,
  type Channel,
  type ChannelMessage,
} from "./types.js";

export class BulletinStore {
  constructor(readonly store: Store) {}
  async cursor(channel: Channel): Promise<number | null> {
    const { rows } = await this.store.pool.query(
      "SELECT high_id FROM obriy.channel_cursors WHERE channel=$1",
      [channel],
    );
    return rows[0] ? Number(rows[0].high_id) : null;
  }
  async ingest(
    channel: Channel,
    messages: ChannelMessage[],
    highId: number,
    initialized: boolean,
    complete: boolean,
    backfill: { before: number; highId: number } | null = null,
  ) {
    await this.store.transaction(async (c) => {
      for (const message of messages) {
        const id = randomUUID();
        const prior = await c.query(
          "SELECT id,content_hash FROM obriy.channel_messages WHERE channel=$1 AND message_id=$2 FOR UPDATE",
          [channel, message.messageId],
        );
        if (prior.rows[0]?.content_hash === message.contentHash) continue;
        const mid = prior.rows[0]?.id ?? id;
        const dataEnc = this.store.vault.encrypt(message, `bulletin:${mid}`);
        const result = await c.query(
          `INSERT INTO obriy.channel_messages(id,channel,message_id,published_at,received_at,content_hash,data_enc,eligible)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(channel,message_id) DO UPDATE SET
          received_at=$5,content_hash=$6,data_enc=$7,revision=obriy.channel_messages.revision+1,
          eligible=obriy.channel_messages.eligible RETURNING revision`,
          [
            mid,
            channel,
            message.messageId,
            message.publishedAt,
            message.receivedAt,
            message.contentHash,
            dataEnc,
            initialized && complete,
          ],
        );
        await c.query(
          "INSERT INTO obriy.channel_message_revisions(message_id,revision,data_enc) VALUES($1,$2,$3)",
          [mid, result.rows[0].revision, dataEnc],
        );
        // Invalidate old queued content immediately, even if the parser worker is delayed.
        await c.query(
          `UPDATE obriy.notification_outbox SET status='cancelled' WHERE bulletin_decision_id IN
          (SELECT id FROM obriy.bulletin_decisions WHERE message_id=$1) AND status IN ('pending','sending')`,
          [mid],
        );
      }
      if (complete)
        await c.query(
          `INSERT INTO obriy.channel_cursors(channel,high_id,last_success_at) VALUES($1,$2,now())
        ON CONFLICT(channel) DO UPDATE SET high_id=GREATEST(obriy.channel_cursors.high_id,$2),last_success_at=now()`,
          [channel, highId],
        );
      await c.query(
        `INSERT INTO obriy.runtime_state(key,data) VALUES($1,$2::jsonb) ON CONFLICT(key) DO UPDATE SET data=$2::jsonb,updated_at=now()`,
        [`bulletin-backfill:${channel}`, JSON.stringify(backfill)],
      );
    });
  }
  async deliveryReady(): Promise<boolean> {
    const config = this.store.config;
    if (
      config.OBRIY_BULLETIN_MODE !== "live" ||
      config.OBRIY_BULLETIN_APPROVED !== "true"
    )
      return false;
    const { rows } = await this.store.pool.query(
      `SELECT count(*)::int AS n FROM obriy.channel_cursors
      WHERE channel=ANY($1::text[]) AND last_success_at>now()-interval '90 seconds'`,
      [CHANNELS],
    );
    return rows[0].n > 0;
  }
  async processOne(): Promise<boolean> {
    if (
      !(
        await this.store.pool.query(
          "SELECT 1 FROM obriy.channel_messages WHERE processed_revision<revision LIMIT 1",
        )
      ).rowCount
    )
      return false;
    const deliveryReady = await this.deliveryReady();
    return this.store.transaction(async (c) => {
      // Same lock order as zone edits / pause / delivery completion.
      await c.query("SELECT id FROM obriy.users ORDER BY id FOR UPDATE");
      const pending = await c.query(
        `SELECT * FROM obriy.channel_messages WHERE processed_revision<revision ORDER BY received_at,id FOR UPDATE SKIP LOCKED LIMIT 1`,
      );
      const row = pending.rows[0];
      if (!row) return false;
      const message = this.store.vault.decrypt<ChannelMessage>(
        row.data_enc,
        `bulletin:${row.id}`,
      );
      const zones = await c.query(
        "SELECT * FROM obriy.zones WHERE enabled ORDER BY id FOR UPDATE",
      );
      const zoneData = new Map(
        zones.rows.map((z) => [
          z.id,
          this.store.vault.decrypt<Omit<Zone, "id" | "userId">>(
            z.data_enc,
            `zone:${z.id}:${z.user_id}`,
          ),
        ]),
      );
      const selected = new Map(
        zones.rows.map((z) => [z.id, zoneAreas(zoneData.get(z.id)!)]),
      );
      const catalogue = [
        ...new Map(
          [...AREAS, ...[...selected.values()].flat()].map((a) => [a.id, a]),
        ).values(),
      ];
      const parsed = parseBulletin(message.text, catalogue);
      const old: Bulletin | null = row.parsed;
      const fingerprint = hash(
        JSON.stringify([parsed.kind, parsed.areaIds, Boolean(parsed.urgent)]),
      );
      for (const z of zones.rows) {
        const zone = this.store.vault.decrypt<Omit<Zone, "id" | "userId">>(
          z.data_enc,
          `zone:${z.id}:${z.user_id}`,
        );
        const localAreas = selected.get(z.id)!;
        const subscriptions = [
          ...new Set([
            ...localAreas.map((a) => a.id),
            ...localAreas.flatMap((a) => (a.parent ? [a.parent] : [])),
          ]),
        ];
        const matches = [
          ...new Set([
            ...matchingAreas(subscriptions, parsed.areaIds),
            ...parsed.areaIds.filter((id) => subscriptions.includes(id)),
          ]),
        ];
        if (
          parsed.urgent &&
          zone.ballisticWarnings !== false &&
          parsed.areaIds.includes("ballistic-general")
        )
          matches.push("ballistic-general");
        const previousSent = await c.query(
          `SELECT d.area_ids FROM obriy.bulletin_decisions d
          JOIN obriy.notifications n ON n.outbox_id IN (SELECT id FROM obriy.notification_outbox WHERE bulletin_decision_id=d.id)
          WHERE d.message_id=$1 AND d.zone_id=$2 AND d.zone_revision=$3 LIMIT 1`,
          [row.id, z.id, z.revision],
        );
        const correction =
          previousSent.rowCount &&
          old?.kind === "warning" &&
          (parsed.kind !== "warning" ||
            previousSent.rows[0].area_ids.some(
              (id: string) => !matches.includes(id),
            ));
        if (!matches.length && !correction) continue;
        const decisionId = randomUUID();
        const decisionAreas: string[] = correction
          ? previousSent.rows[0].area_ids
          : matches;
        await c.query(
          `INSERT INTO obriy.bulletin_decisions(id,message_id,zone_id,zone_revision,message_revision,area_ids,fingerprint)
          VALUES($1,$2,$3,$4,$5,$6,$7)`,
          [
            decisionId,
            row.id,
            z.id,
            z.revision,
            row.revision,
            JSON.stringify(decisionAreas),
            fingerprint,
          ],
        );
        const basis = correction ? message.receivedAt : message.publishedAt;
        const age = Date.now() - Date.parse(basis);
        if (
          !deliveryReady ||
          !row.eligible ||
          age < 0 ||
          age > this.store.config.OBRIY_BULLETIN_MAX_AGE_MS ||
          (parsed.kind !== "warning" && !correction)
        )
          continue;
        const duplicate = await c.query(
          `SELECT 1 FROM obriy.bulletin_decisions d
          JOIN obriy.notification_outbox o ON o.bulletin_decision_id=d.id
          JOIN obriy.channel_messages m ON m.id=d.message_id
          WHERE o.user_id=$1 AND o.status IN ('pending','sending','sent')
          AND d.area_ids @> $3::jsonb
          AND (d.message_id=$2 OR COALESCE((m.parsed->>'urgent')::boolean,false)=$4)
          AND abs(extract(epoch FROM (m.published_at-$5::timestamptz))*1000)<=$6 LIMIT 1`,
          [
            z.user_id,
            row.id,
            JSON.stringify(decisionAreas),
            Boolean(parsed.urgent),
            message.publishedAt,
            this.store.config.OBRIY_BULLETIN_COOLDOWN_MS,
          ],
        );
        if (duplicate.rowCount && !correction) continue;
        if (
          previousSent.rowCount &&
          !correction &&
          old &&
          JSON.stringify(old) === JSON.stringify(parsed)
        )
          continue;
        const names = decisionAreas.map(areaLabel).filter(Boolean).join(", ");
        const text = correction
          ? `Обрій · ${zone.label}\nУточнення: джерело змінило попереднє оголошення для ${names}. Це не означає відбій тривоги.\n${message.url}`
          : `Обрій · ${zone.label}\n${parsed.urgent ? "🔴 HIGH · Балістика / ОТРК · прямуйте в укриття" : parsed.uncertain ? "Можлива загроза" : "⚠️ Згадка джерела для вашого місця"}: ${names}.\nЗбіг із населеним пунктом у радіусі або додатковою підпискою. Загальне попередження не визначає місце загрози.\nЧас джерела: ${new Intl.DateTimeFormat("uk-UA", { timeZone: "Europe/Kyiv", hour: "2-digit", minute: "2-digit" }).format(new Date(message.publishedAt))}\n${message.url}\nПеревіряйте офіційну тривогу та дотримуйтеся вказівок цивільного захисту.`;
        const outboxId = randomUUID();
        await c.query(
          `INSERT INTO obriy.notification_outbox(id,dedupe_key,user_id,zone_id,payload_enc,category,expires_at,bulletin_decision_id)
          SELECT $1,$2,id,$4,$5,'telegram_observation',$6,$7 FROM obriy.users
          WHERE id=$3 AND chat_enc IS NOT NULL AND (paused_until IS NULL OR paused_until<=now()) ON CONFLICT(dedupe_key) DO NOTHING`,
          [
            outboxId,
            `bulletin:${decisionId}`,
            z.user_id,
            z.id,
            this.store.vault.encrypt(
              {
                text,
                level: correction
                  ? "CORRECTION"
                  : parsed.urgent
                    ? "HIGH"
                    : "BULLETIN",
              },
              `outbox:${outboxId}`,
            ),
            new Date(
              Date.parse(basis) + this.store.config.OBRIY_BULLETIN_MAX_AGE_MS,
            ),
            decisionId,
          ],
        );
      }
      await c.query(
        "UPDATE obriy.channel_messages SET parsed=$2,processed_revision=revision WHERE id=$1",
        [row.id, parsed],
      );
      return true;
    });
  }
  async feed(userId: string) {
    const { rows } = await this.store.pool.query(
      `SELECT d.id,d.zone_id,d.area_ids,d.created_at,d.fingerprint,m.channel,m.message_id,m.published_at,m.parsed
      FROM obriy.bulletin_decisions d JOIN obriy.zones z ON z.id=d.zone_id JOIN obriy.channel_messages m ON m.id=d.message_id
      WHERE z.user_id=$1 AND z.enabled AND z.revision=d.zone_revision AND d.message_revision=m.revision
      AND m.parsed->>'kind'<>'other' ORDER BY d.created_at DESC LIMIT 100`,
      [userId],
    );
    return rows.map((r) => ({
      id: r.id,
      zoneId: r.zone_id,
      areaIds: r.area_ids,
      areaNames: r.area_ids.map(areaLabel),
      urgent: Boolean(r.parsed.urgent),
      publishedAt: r.published_at.toISOString(),
      kind: r.parsed.kind,
      uncertain: r.parsed.uncertain,
      reasons: r.parsed.reasons,
      source: r.channel,
      url: `https://t.me/${r.channel}/${r.message_id}`,
    }));
  }
}
