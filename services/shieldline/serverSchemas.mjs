import { z } from "zod";

const coordinates = z.object({ lat: z.number().min(43).max(53.5), lng: z.number().min(20).max(41.5) }).strict();
const assetKind = z.enum(["radar", "mvg", "boat", "ew", "manpads", "gepard", "buk", "s300", "iris-t", "nasams", "patriot", "drone-operators"]);
const asset = z.object({
  id: z.string().min(1).max(120).regex(/^[a-z0-9_-]+$/i).optional(),
  kind: assetKind,
  cityId: z.string().min(1).max(48).regex(/^[a-z0-9-]+$/),
  readiness: z.number().min(0).max(100),
  position: coordinates.optional(),
}).strict();

export const defensePlanSchema = z.object({
  assetCount: z.number().int().min(0).max(32),
  radarCount: z.number().int().min(0).max(32),
  kineticCount: z.number().int().min(0).max(32),
  averageReadiness: z.number().min(0).max(100),
  assets: z.array(asset).max(32),
}).strict().superRefine((plan, context) => {
  if (plan.assetCount !== plan.assets.length) context.addIssue({ code: "custom", path: ["assetCount"], message: "assetCount must match assets.length." });
  const radarCount = plan.assets.filter((entry) => entry.kind === "radar").length;
  if (plan.radarCount !== radarCount) context.addIssue({ code: "custom", path: ["radarCount"], message: "radarCount does not match the submitted assets." });
});

const operationSchema = z.object({
  modeId: z.enum(["campaign", "rapid-response", "ranked-challenge", "co-op-command", "sandbox", "training"]),
  missionId: z.string().min(1).max(64).regex(/^[a-z0-9-]+$/),
  seed: z.string().min(8).max(80).regex(/^[a-z0-9_-]+$/i),
  simVersion: z.string().max(24).optional(),
  plan: defensePlanSchema,
}).strict();

const commandSchema = z.object({
  commandId: z.string().min(8).max(96).regex(/^[a-z0-9_-]+$/i),
  baseRevision: z.number().int().min(1),
  scope: z.object({ type: z.enum(["operation", "sector"]), sectorId: z.enum(["north", "south", "east", "west", "hq"]).optional() }).strict(),
  type: z.string().min(1).max(64).regex(/^[a-z0-9._-]+$/i),
  payload: z.record(z.string(), z.unknown()),
}).strict();

const campaignCommandSchema = z.object({
  type: z.string().min(1).max(64).regex(/^[a-z0-9._-]+$/i),
  payload: z.record(z.string(), z.unknown()).default({}),
}).strict();
const analyticsSchema = z.object({
  eventName: z.enum(["app.open", "telegram.authenticated", "campaign.asset.placed", "campaign.operation.started", "campaign.operation.completed", "campaign.reconnected", "pwa.offline.queued"]),
  channel: z.enum(["telegram", "pwa", "web"]),
  sessionId: z.string().min(8).max(96),
  occurredAt: z.string().datetime(),
  properties: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).default({}),
}).strict();

const deviceToken = z.string().min(32).max(128).regex(/^[A-Za-z0-9_-]+$/);
const telegramInitData = z.string().min(1).max(8192);
const reservedNicknames = new Set(["admin", "administrator", "moderator", "support", "shieldline"]);

export function normalizeNickname(value) {
  return String(value || "").normalize("NFKC").trim().replace(/\s+/g, " ").toLocaleLowerCase("uk-UA");
}

const nickname = z.string().transform((value) => String(value).normalize("NFKC").trim().replace(/\s+/g, " ")).pipe(
  z.string().min(3).max(24).regex(/^[\p{L}\p{N}](?:[\p{L}\p{N} ._-]*[\p{L}\p{N}])?$/u, "Nickname contains unsupported characters."),
).superRefine((value, context) => {
  if (reservedNicknames.has(normalizeNickname(value))) context.addIssue({ code: "custom", message: "This nickname is reserved." });
});

const authBootstrapSchema = z.object({
  deviceToken: deviceToken.optional(),
  telegramInitData: telegramInitData.optional(),
}).strict();

const authRegistrationSchema = z.object({
  nickname,
  deviceToken,
  consentAccepted: z.literal(true),
  consentVersion: z.string().min(1).max(48),
  telegramInitData: telegramInitData.optional(),
}).strict();

const nicknameAvailabilitySchema = z.object({ nickname }).strict();
const transferRedeemSchema = z.object({
  code: z.string().regex(/^\d{6}$/),
  deviceToken,
  telegramInitData: telegramInitData.optional(),
}).strict();
const telegramLinkSchema = z.object({ telegramInitData }).strict();
const playerProgressSchema = z.object({
  baseRevision: z.number().int().min(0),
  state: z.record(z.string(), z.unknown()),
}).strict();

function parse(schema, value) {
  const result = schema.safeParse(value);
  if (result.success) return result.data;
  throw Object.assign(new Error("Request payload failed validation."), {
    statusCode: 422,
    validationIssues: result.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })),
  });
}

export function parseOperationInput(value) { return parse(operationSchema, value); }
export function parseOperationCommand(value) { return parse(commandSchema, value); }
export function parseCampaignCommand(value) { return parse(campaignCommandSchema, value); }
export function parseAnalyticsEvent(value) { return parse(analyticsSchema, value); }
export function parseAuthBootstrap(value) { return parse(authBootstrapSchema, value); }
export function parseAuthRegistration(value) { return parse(authRegistrationSchema, value); }
export function parseNicknameAvailability(value) { return parse(nicknameAvailabilitySchema, value); }
export function parseTransferRedeem(value) { return parse(transferRedeemSchema, value); }
export function parseTelegramLink(value) { return parse(telegramLinkSchema, value); }
export function parsePlayerProgress(value) { return parse(playerProgressSchema, value); }
