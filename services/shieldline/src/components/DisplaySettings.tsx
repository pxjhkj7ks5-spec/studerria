import { Cloud, CloudFog, CloudRain, Gauge, Moon, Sun } from "lucide-react";
import type { DisplayPreferences, EnvironmentTime, EnvironmentWeather } from "../platform/displayPreferences";

const timeOptions: Array<{ id: EnvironmentTime; label: string; icon: typeof Sun }> = [
  { id: "day", label: "День", icon: Sun },
  { id: "night", label: "Ніч", icon: Moon },
];

const weatherOptions: Array<{ id: EnvironmentWeather; label: string; icon: typeof Sun }> = [
  { id: "clear", label: "Ясно", icon: Sun },
  { id: "cloudy", label: "Хмарно", icon: Cloud },
  { id: "fog", label: "Туман", icon: CloudFog },
  { id: "rain", label: "Дощ", icon: CloudRain },
];

interface DisplaySettingsProps {
  preferences: DisplayPreferences;
  onChange: (preferences: DisplayPreferences) => void;
}

export function DisplaySettings({ preferences, onChange }: DisplaySettingsProps) {
  return (
    <section className="display-settings" aria-label="Візуальні налаштування Shieldline">
      <header>
        <div><strong>Тестове середовище</strong><span>Лише візуальний шар мапи</span></div>
      </header>
      <div className="display-settings__group">
        <span>Час</span>
        <div className="display-settings__segments">
          {timeOptions.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" className={preferences.environmentTime === id ? "is-active" : ""} aria-pressed={preferences.environmentTime === id} onClick={() => onChange({ ...preferences, environmentTime: id })}>
              <Icon size={15} /> {label}
            </button>
          ))}
        </div>
      </div>
      <div className="display-settings__group">
        <span>Погода</span>
        <div className="display-settings__segments display-settings__segments--weather">
          {weatherOptions.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" className={preferences.environmentWeather === id ? "is-active" : ""} aria-pressed={preferences.environmentWeather === id} onClick={() => onChange({ ...preferences, environmentWeather: id })}>
              <Icon size={15} /> {label}
            </button>
          ))}
        </div>
      </div>
      <label className="performance-toggle">
        <span><Gauge size={18} /><span><strong>Режим продуктивності</strong><small>Спрощує ефекти та анімації</small></span></span>
        <input type="checkbox" checked={preferences.performanceMode} onChange={(event) => onChange({ ...preferences, performanceMode: event.target.checked })} />
        <i aria-hidden="true" />
      </label>
    </section>
  );
}
