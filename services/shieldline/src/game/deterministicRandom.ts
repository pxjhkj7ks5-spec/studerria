export const SIM_VERSION = "2.1.0";

function hash32(value: string) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash = Math.imul(hash ^ value.charCodeAt(index), 16777619);
  }
  hash += 0x6d2b79f5;
  hash = Math.imul(hash ^ (hash >>> 15), hash | 1);
  hash ^= hash + Math.imul(hash ^ (hash >>> 7), hash | 61);
  return (hash ^ (hash >>> 14)) >>> 0;
}

export function createDeterministicRandom(seed: string, initialCursor = 0) {
  let cursor = initialCursor;
  return {
    next() {
      const value = hash32(`${SIM_VERSION}:${seed}:${cursor}`) / 4294967296;
      cursor += 1;
      return value;
    },
    cursor() {
      return cursor;
    },
  };
}
