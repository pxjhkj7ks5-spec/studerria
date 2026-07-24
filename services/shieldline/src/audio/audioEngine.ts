import { defaultAudioPreferences, normalizeAudioPreferences, readAudioPreferences, type AudioPreferences } from "../platform/audioPreferences";
import { cueAllowedAt, selectSoundVariant, soundCueDefinitions, type SoundCategory, type SoundCue } from "./soundCues";

interface ActiveVoice {
  cue: SoundCue;
  source: AudioBufferSourceNode;
  gain: GainNode;
  startedAt: number;
}

type AudioContextConstructor = typeof AudioContext;

function audioContextConstructor() {
  if (typeof window === "undefined") return null;
  const audioWindow = window as typeof window & { webkitAudioContext?: AudioContextConstructor };
  return window.AudioContext || audioWindow.webkitAudioContext || null;
}

export class ShieldlineAudioEngine {
  private context: AudioContext | null = null;
  private masterGain: GainNode | null = null;
  private categoryGains: Partial<Record<SoundCategory, GainNode>> = {};
  private buffers = new Map<string, Promise<AudioBuffer>>();
  private activeVoices: ActiveVoice[] = [];
  private lastPlayedAt = new Map<SoundCue, number>();
  private lastVariant = new Map<SoundCue, number>();
  private preferences: AudioPreferences = readAudioPreferences();
  private visible = typeof document === "undefined" || !document.hidden;
  private unlocked = false;
  private duckRestoreTimer: number | null = null;
  private criticalRequestId = 0;

  get currentPreferences() {
    return { ...this.preferences };
  }

  get isUnlocked() {
    return this.unlocked;
  }

  async unlock() {
    if (!this.preferences.enabled || !this.visible) return false;
    const context = this.ensureContext();
    if (!context) return false;
    try {
      if (context.state === "suspended") await context.resume();
      this.unlocked = context.state === "running";
      return this.unlocked;
    } catch {
      return false;
    }
  }

  setPreferences(value: AudioPreferences) {
    this.preferences = normalizeAudioPreferences(value);
    this.applyVolumes();
    if (!this.preferences.enabled) this.stopAll();
  }

  setVisible(visible: boolean) {
    this.visible = visible;
    if (!visible) {
      this.stopAll();
      if (this.context?.state === "running") void this.context.suspend().catch(() => undefined);
    } else if (this.unlocked && this.preferences.enabled && this.context?.state === "suspended") {
      void this.context.resume().catch(() => undefined);
    }
  }

  async play(cue: SoundCue, now = performance.now()) {
    if (!this.preferences.enabled || !this.visible || !this.unlocked || !cueAllowedAt(cue, this.lastPlayedAt.get(cue), now)) return false;
    const definition = soundCueDefinitions[cue];
    const variantIndex = selectSoundVariant(cue, this.lastVariant.get(cue));
    const variant = definition.variants[variantIndex];
    const context = this.ensureContext();
    const destination = this.categoryGains[definition.category];
    if (!context || !destination || context.state !== "running") return false;

    this.lastPlayedAt.set(cue, now);
    this.lastVariant.set(cue, variantIndex);
    const criticalRequestId = definition.priority === 3 ? ++this.criticalRequestId : this.criticalRequestId;
    try {
      const buffer = await this.loadBuffer(variant.file);
      if (!this.preferences.enabled || !this.visible || context.state !== "running" || (definition.priority === 3 && criticalRequestId !== this.criticalRequestId)) return false;
      if (definition.priority === 3) this.stopCriticalVoices();
      this.trimVoices(cue, definition.maxVoices);
      const source = context.createBufferSource();
      const gain = context.createGain();
      source.buffer = buffer;
      source.playbackRate.value = variant.playbackRate || 1;
      gain.gain.value = variant.gain ?? 1;
      source.connect(gain);
      gain.connect(destination);
      const voice: ActiveVoice = { cue, source, gain, startedAt: context.currentTime };
      this.activeVoices.push(voice);
      source.addEventListener("ended", () => this.removeVoice(voice), { once: true });
      const offset = Math.max(0, Math.min(variant.offset || 0, Math.max(0, buffer.duration - 0.01)));
      const duration = Math.max(0.02, Math.min(variant.duration || buffer.duration - offset, buffer.duration - offset));
      if (definition.priority === 3) this.duckLowerPriorities(duration);
      source.start(0, offset, duration);
      return true;
    } catch {
      this.buffers.delete(variant.file);
      return false;
    }
  }

  async preview(cue: SoundCue) {
    if (!await this.unlock()) return false;
    this.stopAll();
    this.lastPlayedAt.delete(cue);
    return this.play(cue, performance.now());
  }

  stopAll() {
    this.criticalRequestId += 1;
    if (this.duckRestoreTimer !== null) {
      window.clearTimeout(this.duckRestoreTimer);
      this.duckRestoreTimer = null;
    }
    for (const voice of [...this.activeVoices]) {
      try { voice.source.stop(); } catch { /* Voice may have ended between frames. */ }
      this.removeVoice(voice);
    }
  }

  private ensureContext() {
    if (this.context) return this.context;
    const Constructor = audioContextConstructor();
    if (!Constructor) return null;
    try {
      this.context = new Constructor();
      this.masterGain = this.context.createGain();
      this.masterGain.connect(this.context.destination);
      for (const category of ["ui", "combat", "critical"] as const) {
        const gain = this.context.createGain();
        gain.connect(this.masterGain);
        this.categoryGains[category] = gain;
      }
      this.applyVolumes();
      return this.context;
    } catch {
      this.context = null;
      return null;
    }
  }

  private applyVolumes() {
    if (!this.context || !this.masterGain) return;
    const now = this.context.currentTime;
    this.masterGain.gain.setTargetAtTime(this.preferences.enabled ? this.preferences.masterVolume : 0, now, 0.015);
    this.categoryGains.ui?.gain.setTargetAtTime(this.preferences.interfaceVolume, now, 0.015);
    this.categoryGains.combat?.gain.setTargetAtTime(this.preferences.combatVolume, now, 0.015);
    this.categoryGains.critical?.gain.setTargetAtTime(this.preferences.combatVolume, now, 0.015);
  }

  private async loadBuffer(file: string) {
    const cached = this.buffers.get(file);
    if (cached) return cached;
    const context = this.ensureContext();
    if (!context) throw new Error("Web Audio is unavailable");
    const promise = fetch(`${import.meta.env.BASE_URL}${file}`)
      .then((response) => {
        if (!response.ok) throw new Error(`Audio request failed: ${response.status}`);
        return response.arrayBuffer();
      })
      .then((data) => context.decodeAudioData(data));
    this.buffers.set(file, promise);
    return promise;
  }

  private trimVoices(cue: SoundCue, maxVoices: number) {
    const cueVoices = this.activeVoices.filter((voice) => voice.cue === cue).sort((left, right) => left.startedAt - right.startedAt);
    while (cueVoices.length >= maxVoices) {
      const voice = cueVoices.shift();
      if (!voice) break;
      try { voice.source.stop(); } catch { /* Already stopped. */ }
      this.removeVoice(voice);
    }
    const globalVoices = [...this.activeVoices].sort((left, right) => left.startedAt - right.startedAt);
    while (globalVoices.length >= 8) {
      const voice = globalVoices.shift();
      if (!voice) break;
      try { voice.source.stop(); } catch { /* Already stopped. */ }
      this.removeVoice(voice);
    }
  }

  private stopCriticalVoices() {
    for (const voice of [...this.activeVoices]) {
      if (soundCueDefinitions[voice.cue].priority !== 3) continue;
      try { voice.source.stop(); } catch { /* Already stopped. */ }
      this.removeVoice(voice);
    }
  }

  private duckLowerPriorities(durationSeconds: number) {
    if (!this.context) return;
    const now = this.context.currentTime;
    this.categoryGains.ui?.gain.setTargetAtTime(this.preferences.interfaceVolume * 0.2, now, 0.02);
    this.categoryGains.combat?.gain.setTargetAtTime(this.preferences.combatVolume * 0.28, now, 0.02);
    if (this.duckRestoreTimer !== null) window.clearTimeout(this.duckRestoreTimer);
    this.duckRestoreTimer = window.setTimeout(() => {
      if (!this.context) return;
      const restoreAt = this.context.currentTime;
      this.categoryGains.ui?.gain.setTargetAtTime(this.preferences.interfaceVolume, restoreAt, 0.08);
      this.categoryGains.combat?.gain.setTargetAtTime(this.preferences.combatVolume, restoreAt, 0.08);
      this.duckRestoreTimer = null;
    }, Math.min(4_000, Math.max(650, durationSeconds * 700)));
  }

  private removeVoice(voice: ActiveVoice) {
    this.activeVoices = this.activeVoices.filter((candidate) => candidate !== voice);
    try { voice.source.disconnect(); } catch { /* Already disconnected. */ }
    try { voice.gain.disconnect(); } catch { /* Already disconnected. */ }
  }
}

export const shieldlineAudio = new ShieldlineAudioEngine();

export function playSound(cue: SoundCue) {
  return shieldlineAudio.play(cue);
}

export function previewSound(cue: SoundCue) {
  return shieldlineAudio.preview(cue);
}

export function resetAudioPreferencesForTests() {
  shieldlineAudio.setPreferences(defaultAudioPreferences);
}
