export interface AudioPreferences {
  enabled: boolean;
  masterVolume: number;
  combatVolume: number;
  interfaceVolume: number;
}

export const AUDIO_PREFERENCES_KEY = "shieldline-audio-preferences-v1";

export const defaultAudioPreferences: AudioPreferences = {
  enabled: true,
  masterVolume: 0.65,
  combatVolume: 0.9,
  interfaceVolume: 0.55,
};

function normalizedVolume(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isFinite(value)
    ? Math.max(0, Math.min(1, value))
    : fallback;
}

export function normalizeAudioPreferences(value: unknown): AudioPreferences {
  const input = value && typeof value === "object" ? value as Partial<AudioPreferences> : {};
  return {
    enabled: input.enabled !== false,
    masterVolume: normalizedVolume(input.masterVolume, defaultAudioPreferences.masterVolume),
    combatVolume: normalizedVolume(input.combatVolume, defaultAudioPreferences.combatVolume),
    interfaceVolume: normalizedVolume(input.interfaceVolume, defaultAudioPreferences.interfaceVolume),
  };
}

export function readAudioPreferences(): AudioPreferences {
  if (typeof window === "undefined") return defaultAudioPreferences;
  try {
    return normalizeAudioPreferences(JSON.parse(window.localStorage.getItem(AUDIO_PREFERENCES_KEY) || "null"));
  } catch {
    return defaultAudioPreferences;
  }
}

export function writeAudioPreferences(preferences: AudioPreferences) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(AUDIO_PREFERENCES_KEY, JSON.stringify(normalizeAudioPreferences(preferences)));
  } catch {
    // Audio remains optional when the host blocks local storage.
  }
}
