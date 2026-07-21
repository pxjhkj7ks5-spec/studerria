import { Cloud, CloudFog, CloudRain, Crosshair, Gauge, MousePointerClick, Moon, Sun, Volume2, VolumeX } from "lucide-react";
import type { DisplayPreferences, EnvironmentTime, EnvironmentWeather } from "../platform/displayPreferences";
import type { AudioPreferences } from "../platform/audioPreferences";

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
  audioPreferences: AudioPreferences;
  onAudioChange: (preferences: AudioPreferences) => void;
}

function percent(value: number) {
  return `${Math.round(value * 100)}%`;
}

export function DisplaySettings({ preferences, onChange, audioPreferences, onAudioChange }: DisplaySettingsProps) {
  return (
    <section className="display-settings" aria-label="Налаштування середовища та звуку Shieldline">
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
      <section className="audio-settings" aria-label="Налаштування звуку">
        <header>
          <span className="audio-settings__icon">{audioPreferences.enabled ? <Volume2 size={18} /> : <VolumeX size={18} />}</span>
          <span><strong>Звуковий супровід</strong><small>Тривоги, бойова робота та команди</small></span>
          <label className="audio-toggle" aria-label="Увімкнути звуковий супровід">
            <input type="checkbox" checked={audioPreferences.enabled} onChange={(event) => onAudioChange({ ...audioPreferences, enabled: event.target.checked })} />
            <i aria-hidden="true" />
          </label>
        </header>
        <label className="audio-volume-row">
          <span><Volume2 size={15} /><span>Загальна гучність</span><output>{percent(audioPreferences.masterVolume)}</output></span>
          <input aria-label="Загальна гучність" type="range" min="0" max="1" step="0.05" value={audioPreferences.masterVolume} disabled={!audioPreferences.enabled} onChange={(event) => onAudioChange({ ...audioPreferences, masterVolume: Number(event.target.value) })} />
        </label>
        <label className="audio-volume-row">
          <span><Crosshair size={15} /><span>Бойові події</span><output>{percent(audioPreferences.combatVolume)}</output></span>
          <input aria-label="Гучність бойових подій" type="range" min="0" max="1" step="0.05" value={audioPreferences.combatVolume} disabled={!audioPreferences.enabled} onChange={(event) => onAudioChange({ ...audioPreferences, combatVolume: Number(event.target.value) })} />
        </label>
        <label className="audio-volume-row">
          <span><MousePointerClick size={15} /><span>Інтерфейс</span><output>{percent(audioPreferences.interfaceVolume)}</output></span>
          <input aria-label="Гучність інтерфейсу" type="range" min="0" max="1" step="0.05" value={audioPreferences.interfaceVolume} disabled={!audioPreferences.enabled} onChange={(event) => onAudioChange({ ...audioPreferences, interfaceVolume: Number(event.target.value) })} />
        </label>
      </section>
    </section>
  );
}
