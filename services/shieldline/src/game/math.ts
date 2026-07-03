export function clamp(value: number, min = 0, max = 100) {
  return Math.max(min, Math.min(max, value));
}

export function pick<T>(items: T[], random: () => number): T {
  return items[Math.floor(random() * items.length)] || items[0];
}

export function weightedChance(score: number, random: () => number) {
  return random() * 100 <= clamp(score);
}

export function createId(prefix: string, day: number, random: () => number) {
  return `${prefix}-${day}-${Math.floor(random() * 100000).toString(36)}`;
}
