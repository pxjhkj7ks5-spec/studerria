export interface SoundSource {
  file: string;
  work: string;
  creator: string;
  sourceUrl: string;
}

const soundSources: Record<string, SoundSource> = {
  "audio/sfx/air-raid.mp3": {
    file: "air-raid.mp3",
    work: "carterallclear.mp3",
    creator: "guitarguy1985",
    sourceUrl: "https://freesound.org/s/57807/",
  },
  "audio/sfx/chime.mp3": {
    file: "chime.mp3",
    work: "Chime Notification",
    creator: "Jofae",
    sourceUrl: "https://freesound.org/s/380482/",
  },
  "audio/sfx/confirm.mp3": {
    file: "confirm.mp3",
    work: "beep.wav",
    creator: "SamsterBirdies",
    sourceUrl: "https://freesound.org/s/561347/",
  },
  "audio/sfx/drone.mp3": {
    file: "drone.mp3",
    work: "Mini Quadrocopter / Drone Sound",
    creator: "euromir",
    sourceUrl: "https://freesound.org/s/365428/",
  },
  "audio/sfx/gun-burst-1.mp3": {
    file: "gun-burst-1.mp3",
    work: "Silenced SMG Three-Shot Burst",
    creator: "qubodup",
    sourceUrl: "https://freesound.org/s/740120/",
  },
  "audio/sfx/impact.mp3": {
    file: "impact.mp3",
    work: "Huge Explosion",
    creator: "florianreichelt",
    sourceUrl: "https://freesound.org/s/459973/",
  },
  "audio/sfx/mechanical.mp3": {
    file: "mechanical.mp3",
    work: "Clink Chunk Mechanical.wav",
    creator: "Geoff-Bremner-Audio",
    sourceUrl: "https://freesound.org/s/669488/",
  },
  "audio/sfx/missile-launch.mp3": {
    file: "missile-launch.mp3",
    work: "bgm-71_tow_missile_launch_1.flac",
    creator: "qubodup",
    sourceUrl: "https://freesound.org/s/67541/",
  },
  "audio/sfx/radio-static.mp3": {
    file: "radio-static.mp3",
    work: "Radio Static",
    creator: "JovianSounds",
    sourceUrl: "https://freesound.org/s/524204/",
  },
  "audio/sfx/rocket-distant.mp3": {
    file: "rocket-distant.mp3",
    work: "Far Away Rocket Launch",
    creator: "qubodup",
    sourceUrl: "https://freesound.org/s/211617/",
  },
  "audio/sfx/timer.mp3": {
    file: "timer.mp3",
    work: "Electronic Timer Beeping 4X",
    creator: "Rudmer_Rotteveel",
    sourceUrl: "https://freesound.org/s/536420/",
  },
};

export function getSoundSource(file: string) {
  return soundSources[file];
}

export function getSoundSources() {
  return Object.values(soundSources);
}
