export const soundCueNames = [
  "ui.open",
  "ui.close",
  "ui.select",
  "ui.confirm",
  "ui.cancel",
  "ui.error",
  "placement.select",
  "placement.success",
  "placement.failure",
  "placement.redeploy",
  "placement.service",
  "planning.toggle",
  "operation.countdown",
  "operation.start",
  "operation.pause",
  "operation.resume",
  "operation.complete",
  "alert.prelaunch",
  "alert.launch.drone",
  "alert.launch.cruise",
  "alert.launch.ballistic",
  "alert.air-raid",
  "alert.clear",
  "contact.detected",
  "contact.classified",
  "contact.lost",
  "engagement.radar",
  "engagement.gun",
  "engagement.missile",
  "engagement.ew",
  "engagement.drone",
  "engagement.reload",
  "result.intercept",
  "result.soft-kill",
  "result.miss",
  "result.impact",
  "result.mission-success",
  "result.mission-failure",
  "result.campaign-complete",
] as const;

export type SoundCue = typeof soundCueNames[number];
export type SoundCategory = "ui" | "combat" | "critical";
export type SoundPriority = 1 | 2 | 3;

export interface SoundVariant {
  file: string;
  offset?: number;
  duration?: number;
  playbackRate?: number;
  gain?: number;
}

export interface SoundCueDefinition {
  category: SoundCategory;
  priority: SoundPriority;
  cooldownMs: number;
  maxVoices: number;
  variants: SoundVariant[];
}

const sfx = (file: string, options: Omit<SoundVariant, "file"> = {}): SoundVariant => ({ file: `audio/sfx/${file}.mp3`, ...options });
const ui = (variants: SoundVariant[], cooldownMs = 70): SoundCueDefinition => ({ category: "ui", priority: 1, cooldownMs, maxVoices: 2, variants });
const combat = (variants: SoundVariant[], cooldownMs = 350, maxVoices = 3): SoundCueDefinition => ({ category: "combat", priority: 2, cooldownMs, maxVoices, variants });
const critical = (variants: SoundVariant[], cooldownMs: number): SoundCueDefinition => ({ category: "critical", priority: 3, cooldownMs, maxVoices: 1, variants });

export const soundCueDefinitions: Record<SoundCue, SoundCueDefinition> = {
  "ui.open": ui([sfx("confirm", { gain: 0.34, playbackRate: 1.08 })]),
  "ui.close": ui([sfx("confirm", { gain: 0.26, playbackRate: 0.82 })]),
  "ui.select": ui([sfx("confirm", { gain: 0.28 })]),
  "ui.confirm": ui([sfx("chime", { gain: 0.42 })], 120),
  "ui.cancel": ui([sfx("mechanical", { gain: 0.22, playbackRate: 1.25 })], 120),
  "ui.error": ui([sfx("timer", { duration: 0.42, gain: 0.3, playbackRate: 0.78 })], 350),
  "placement.select": ui([sfx("mechanical", { gain: 0.28, playbackRate: 1.18 })], 100),
  "placement.success": ui([sfx("mechanical", { gain: 0.42 }), sfx("chime", { gain: 0.34, playbackRate: 0.9 })], 180),
  "placement.failure": ui([sfx("timer", { duration: 0.5, gain: 0.3, playbackRate: 0.74 })], 350),
  "placement.redeploy": ui([sfx("mechanical", { gain: 0.38, playbackRate: 0.86 })], 180),
  "placement.service": ui([sfx("mechanical", { gain: 0.3, playbackRate: 1.08 }), sfx("confirm", { gain: 0.3, playbackRate: 0.92 })], 180),
  "planning.toggle": ui([sfx("confirm", { gain: 0.3, playbackRate: 1.16 })], 100),
  "operation.countdown": combat([sfx("timer", { duration: 3.6, gain: 0.34 })], 3_500, 1),
  "operation.start": combat([sfx("radio-static", { offset: 0.5, duration: 0.65, gain: 0.27 }), sfx("mechanical", { gain: 0.38, playbackRate: 0.78 })], 1_200, 1),
  "operation.pause": ui([sfx("mechanical", { gain: 0.28, playbackRate: 0.7 })], 300),
  "operation.resume": ui([sfx("mechanical", { gain: 0.3, playbackRate: 1.1 })], 300),
  "operation.complete": combat([sfx("radio-static", { offset: 3.2, duration: 0.75, gain: 0.24 })], 2_000, 1),
  "alert.prelaunch": combat([sfx("radio-static", { offset: 1.1, duration: 0.9, gain: 0.38 }), sfx("timer", { duration: 0.75, gain: 0.25 })], 1_400, 1),
  "alert.launch.drone": combat([sfx("drone", { offset: 4.2, duration: 1.8, gain: 0.26 }), sfx("rocket-distant", { offset: 2.1, duration: 1.7, gain: 0.23, playbackRate: 1.12 })], 1_400, 2),
  "alert.launch.cruise": combat([sfx("rocket-distant", { offset: 1.2, duration: 3.2, gain: 0.42 })], 1_600, 2),
  "alert.launch.ballistic": critical([sfx("missile-launch", { duration: 3, gain: 0.58, playbackRate: 0.92 })], 2_200),
  "alert.air-raid": critical([sfx("siren", { offset: 1, duration: 9, gain: 0.36 })], 12_000),
  "alert.clear": critical([sfx("siren", { offset: 9.5, duration: 4.2, gain: 0.22, playbackRate: 0.82 })], 8_000),
  "contact.detected": combat([sfx("confirm", { gain: 0.28, playbackRate: 1.45 }), sfx("radio-static", { offset: 2.2, duration: 0.42, gain: 0.22 })], 700, 2),
  "contact.classified": combat([sfx("confirm", { gain: 0.3, playbackRate: 1.7 })], 650, 2),
  "contact.lost": combat([sfx("radio-static", { offset: 4.2, duration: 0.8, gain: 0.34 })], 850, 2),
  "engagement.radar": combat([sfx("confirm", { gain: 0.2, playbackRate: 1.55 })], 500, 2),
  "engagement.gun": combat([sfx("gun-burst-1", { gain: 0.52 }), sfx("gun-burst-2", { offset: 0.35, duration: 1.15, gain: 0.42, playbackRate: 1.06 })], 260, 3),
  "engagement.missile": combat([sfx("missile-launch", { duration: 2.2, gain: 0.48 }), sfx("rocket-distant", { offset: 1, duration: 2.3, gain: 0.36, playbackRate: 1.15 })], 520, 3),
  "engagement.ew": combat([sfx("radio-static", { offset: 0.8, duration: 1.2, gain: 0.38, playbackRate: 0.72 })], 650, 2),
  "engagement.drone": combat([sfx("drone", { offset: 8, duration: 1.8, gain: 0.32, playbackRate: 1.08 })], 650, 2),
  "engagement.reload": combat([sfx("mechanical", { gain: 0.36, playbackRate: 0.9 })], 900, 2),
  "result.intercept": combat([sfx("impact", { offset: 0.5, duration: 2.3, gain: 0.34, playbackRate: 1.18 }), sfx("chime", { gain: 0.28, playbackRate: 0.88 })], 450, 3),
  "result.soft-kill": combat([sfx("radio-static", { offset: 3, duration: 1.1, gain: 0.3, playbackRate: 0.65 })], 650, 2),
  "result.miss": combat([sfx("radio-static", { offset: 5, duration: 0.6, gain: 0.26 })], 500, 2),
  "result.impact": critical([sfx("impact", { offset: 0.3, duration: 4.5, gain: 0.62 })], 1_000),
  "result.mission-success": critical([sfx("chime", { gain: 0.52, playbackRate: 0.86 })], 4_000),
  "result.mission-failure": critical([sfx("timer", { duration: 2.4, gain: 0.38, playbackRate: 0.58 })], 4_000),
  "result.campaign-complete": critical([sfx("chime", { gain: 0.58 }), sfx("chime", { gain: 0.48, playbackRate: 0.82 })], 5_000),
};

export function selectSoundVariant(cue: SoundCue, previousIndex = -1, random = Math.random) {
  const variants = soundCueDefinitions[cue].variants;
  if (variants.length <= 1) return 0;
  const candidate = Math.floor(random() * variants.length);
  return candidate === previousIndex ? (candidate + 1) % variants.length : candidate;
}

export function cueAllowedAt(cue: SoundCue, lastPlayedAt: number | undefined, now: number) {
  return lastPlayedAt === undefined || now - lastPlayedAt >= soundCueDefinitions[cue].cooldownMs;
}
