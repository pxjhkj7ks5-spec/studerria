export type EnvironmentTime = "day" | "night";
export type EnvironmentWeather = "clear" | "cloudy" | "fog" | "rain";

export interface DisplayPreferences {
  environmentTime: EnvironmentTime;
  environmentWeather: EnvironmentWeather;
  performanceMode: boolean;
}

export const DISPLAY_PREFERENCES_KEY = "shieldline-display-preferences-v1";

export const defaultDisplayPreferences: DisplayPreferences = {
  environmentTime: "night",
  environmentWeather: "clear",
  performanceMode: false,
};

export function normalizeDisplayPreferences(value: unknown): DisplayPreferences {
  const input = value && typeof value === "object" ? value as Partial<DisplayPreferences> : {};
  const environmentTime = input.environmentTime === "day" || input.environmentTime === "night"
    ? input.environmentTime
    : defaultDisplayPreferences.environmentTime;
  const environmentWeather = input.environmentWeather === "clear"
    || input.environmentWeather === "cloudy"
    || input.environmentWeather === "fog"
    || input.environmentWeather === "rain"
    ? input.environmentWeather
    : defaultDisplayPreferences.environmentWeather;
  return {
    environmentTime,
    environmentWeather,
    performanceMode: input.performanceMode === true,
  };
}

export function readDisplayPreferences(): DisplayPreferences {
  if (typeof window === "undefined") return defaultDisplayPreferences;
  try {
    return normalizeDisplayPreferences(JSON.parse(window.localStorage.getItem(DISPLAY_PREFERENCES_KEY) || "null"));
  } catch {
    return defaultDisplayPreferences;
  }
}

export function writeDisplayPreferences(preferences: DisplayPreferences) {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(DISPLAY_PREFERENCES_KEY, JSON.stringify(normalizeDisplayPreferences(preferences)));
  } catch {
    // Visual preferences are optional; storage restrictions must not block the tactical UI.
  }
}

export function resolveReducedQuality(automaticReducedQuality: boolean, performanceMode: boolean) {
  return performanceMode || automaticReducedQuality;
}
