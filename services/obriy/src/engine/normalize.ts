import { createHash } from "node:crypto";
import { z } from "zod";
import { DEFAULT_ENGINE_CONFIG } from "./config.js";
import { normalizeHeading } from "./geometry.js";
import type {
  NormalizedTrack,
  OfficialAlertEvent,
  ThreatType,
} from "./types.js";

const optionalText = z.string().max(1000).nullish();
const optionalFinite = z.number().finite().nullish();
const optionalBoolean = z.boolean().nullish();
const trackSchema = z
  .object({
    id: z.union([z.string().min(1).max(300), z.number().int().safe()]),
    type: z.string().min(1).max(100),
    title: optionalText,
    lat: z.number().finite().min(-90).max(90).nullish(),
    lon: z.number().finite().min(-180).max(180).nullish(),
    heading: optionalFinite,
    velocity: z
      .object({ bearingDeg: optionalFinite, speedKmh: optionalFinite })
      .passthrough()
      .nullish(),
    confirmedAt: optionalText,
    updatedAt: z.string().min(1).max(100),
    uncertaintyKm: z.number().finite().nonnegative().max(20000).nullish(),
    confidenceLevel: optionalText,
    positionQuality: optionalText,
    sourceCount: z.number().int().nonnegative().max(100000).nullish(),
    count: z.number().int().nonnegative().max(100000).nullish(),
    status: optionalText,
    advisory: optionalBoolean,
    areaOnly: optionalBoolean,
    presumptiveCourse: optionalBoolean,
    region: optionalText,
    district: optionalText,
    locality: optionalText,
  })
  .passthrough();

const threatTypes = new Set<string>([
  "uav",
  "fpv",
  "recon",
  "missile",
  "ballistic",
  "kab",
  "mig31k",
  "unknown",
  "other",
]);
const statuses = new Set<string>(["active", "stale", "resolved"]);
const confidenceLevels = new Set<string>(["low", "medium", "high"]);

/** Stable UUIDv5 in the DNS namespace: replay never invents a new track identifier. */
export function deterministicId(input: string): string {
  const namespace = Buffer.from("6ba7b8109dad11d180b400c04fd430c8", "hex");
  const bytes = createHash("sha1")
    .update(namespace)
    .update(input)
    .digest()
    .subarray(0, 16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x50;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function timestamp(
  input: string,
  now: Date,
  futureSkewSeconds = DEFAULT_ENGINE_CONFIG.limits.futureClockSkewSeconds,
): string {
  const parsed = Date.parse(input);
  if (
    !/^\d{4}-\d{2}-\d{2}T/.test(input) ||
    !/(Z|[+-]\d{2}:\d{2})$/.test(input) ||
    !Number.isFinite(parsed) ||
    parsed < Date.UTC(2000, 0, 1) ||
    parsed > now.getTime() + futureSkewSeconds * 1000
  ) {
    throw new Error("Invalid upstream timestamp");
  }
  return new Date(parsed).toISOString();
}
function validNow(now: Date): void {
  if (!Number.isFinite(now.getTime()))
    throw new Error("Invalid evaluation clock");
}
function text(value: string | null | undefined): string | undefined {
  return value?.trim() || undefined;
}

export function normalizeTrack(raw: unknown, now: Date): NormalizedTrack {
  validNow(now);
  const result = trackSchema.safeParse(raw);
  // The Zod error can contain hostile payload and coordinates; never propagate it to logs.
  if (!result.success) throw new Error("Invalid upstream track schema");
  const value = result.data;
  const updatedAt = timestamp(value.updatedAt, now);
  const confirmedAt = value.confirmedAt
    ? timestamp(value.confirmedAt, now, 0)
    : undefined;
  if (confirmedAt && Date.parse(confirmedAt) > Date.parse(updatedAt))
    throw new Error("Invalid upstream timestamp order");
  const areaOnly = value.areaOnly === true;
  const quality =
    value.positionQuality === "confirmed" || value.positionQuality === "approx"
      ? value.positionQuality
      : "unknown";
  const hasCoordinates = !areaOnly && value.lat != null && value.lon != null;
  const rawHeading = value.velocity?.bearingDeg ?? value.heading;
  const speed = value.velocity?.speedKmh;
  return {
    internalId: deterministicId(`neptun:${String(value.id)}`),
    source: {
      primary: "neptun",
      externalTrackId: String(value.id),
      sourceRefs: [],
    },
    threat: {
      type: threatTypes.has(value.type) ? (value.type as ThreatType) : "other",
      upstreamType: value.type,
      title: text(value.title),
      groupCount:
        value.count != null && value.count > 0 ? value.count : undefined,
    },
    position: {
      lat: hasCoordinates ? (value.lat ?? undefined) : undefined,
      lon: hasCoordinates ? (value.lon ?? undefined) : undefined,
      quality,
      uncertaintyKm: value.uncertaintyKm ?? undefined,
      areaOnly,
    },
    motion: {
      headingDeg: rawHeading == null ? undefined : normalizeHeading(rawHeading),
      speedKmh:
        speed != null &&
        speed > 0 &&
        speed <= DEFAULT_ENGINE_CONFIG.limits.maxSpeedKmh
          ? speed
          : undefined,
      confirmedAt,
      presumptive: value.presumptiveCourse === true,
    },
    confidence: {
      upstreamLevel:
        value.confidenceLevel && confidenceLevels.has(value.confidenceLevel)
          ? (value.confidenceLevel as "low" | "medium" | "high")
          : "unknown",
      sourceCount: value.sourceCount ?? undefined,
    },
    geography: {
      region: text(value.region),
      district: text(value.district),
      locality: text(value.locality),
    },
    status:
      value.status && statuses.has(value.status)
        ? (value.status as "active" | "stale" | "resolved")
        : "unknown",
    advisory: value.advisory === true,
    observedAt: confirmedAt ?? updatedAt,
    updatedAt,
    ingestedAt: now.toISOString(),
    rawSchemaVersion: 1,
    raw: value,
  };
}

const alertsInUaSchema = z
  .object({
    alerts: z
      .array(
        z
          .object({
            id: z.union([z.string().min(1).max(300), z.number().int().safe()]),
            location_title: optionalText,
            location_type: optionalText,
            location_uid: z
              .union([z.string().max(300), z.number().int().safe()])
              .nullish(),
            location_oblast: optionalText,
            alert_type: z.string().min(1).max(100),
            started_at: optionalText,
            finished_at: optionalText,
            updated_at: z.string().min(1).max(100),
            calculated: optionalBoolean,
          })
          .passthrough(),
      )
      .max(10000),
  })
  .passthrough();
const neptunAreaSchema = z
  .object({
    key: z.string().min(1).max(300),
    name: z.string().min(1).max(1000),
    oblast: z.string().max(1000),
    since: z.string().min(1).max(100),
  })
  .passthrough();
const neptunAlertsSchema = z
  .object({
    version: z.number().int().nonnegative().optional(),
    updatedAt: z.string().min(1).max(100),
    raions: z.array(neptunAreaSchema).max(10000),
    oblasts: z.array(neptunAreaSchema).max(10000),
  })
  .passthrough();
const alertKinds = new Set<string>([
  "air_raid",
  "artillery_shelling",
  "urban_fights",
  "chemical",
  "nuclear",
]);

/** A full snapshot. Invalid shape throws; it must not be mistaken for an empty all-clear. */
export function normalizeOfficialAlerts(
  raw: unknown,
  provider: "alerts.in.ua" | "neptun",
  now: Date,
): OfficialAlertEvent[] {
  validNow(now);
  if (provider === "neptun") {
    const result = neptunAlertsSchema.safeParse(raw);
    if (!result.success)
      throw new Error("Invalid upstream official alerts schema");
    const { oblasts, raions } = result.data;
    const updatedAt = timestamp(result.data.updatedAt, now);
    return [
      ...oblasts.map((area): OfficialAlertEvent => ({
        provider,
        externalId: `oblast:${area.key}`,
        regionUid: area.key,
        oblast: area.name,
        kind: "air_raid",
        active: true,
        startedAt: timestamp(area.since, now),
        updatedAt,
        ingestedAt: now.toISOString(),
      })),
      ...raions.map((area): OfficialAlertEvent => ({
        provider,
        externalId: `raion:${area.key}`,
        raionUid: area.key,
        oblast: area.oblast || undefined,
        raion: area.name,
        kind: "air_raid",
        active: true,
        startedAt: timestamp(area.since, now),
        updatedAt,
        ingestedAt: now.toISOString(),
      })),
    ];
  }
  const result = alertsInUaSchema.safeParse(raw);
  if (!result.success)
    throw new Error("Invalid upstream official alerts schema");
  return result.data.alerts.map((item) => {
    const startedAt = item.started_at
      ? timestamp(item.started_at, now)
      : undefined;
    if (item.finished_at) timestamp(item.finished_at, now);
    const uid =
      item.location_uid != null ? String(item.location_uid) : undefined;
    return {
      provider,
      externalId: String(item.id),
      regionUid: uid,
      raionUid: item.location_type === "raion" ? uid : undefined,
      oblast:
        text(item.location_oblast) ??
        (item.location_type === "oblast"
          ? text(item.location_title)
          : undefined),
      raion:
        item.location_type === "raion" ? text(item.location_title) : undefined,
      locality:
        item.location_type === "hromada" || item.location_type === "city"
          ? text(item.location_title)
          : undefined,
      kind: alertKinds.has(item.alert_type)
        ? (item.alert_type as OfficialAlertEvent["kind"])
        : "unknown",
      active: !item.finished_at,
      calculated: item.calculated ?? undefined,
      startedAt,
      updatedAt: timestamp(item.updated_at, now),
      ingestedAt: now.toISOString(),
    };
  });
}
