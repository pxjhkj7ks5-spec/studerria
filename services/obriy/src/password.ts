import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
export class AuthError extends Error {
  constructor(
    readonly statusCode: number,
    message: string,
    readonly retryAfter?: number,
  ) {
    super(message);
  }
}
let deriving = false;
export function normalizeUsername(value: string) {
  const name = value.normalize("NFC").trim().toLowerCase();
  if (!/^[\p{L}\p{N}][\p{L}\p{N}_.-]{2,31}$/u.test(name))
    throw new AuthError(
      400,
      "Логін: 3–32 літери або цифри, також можна крапку, дефіс і підкреслення.",
    );
  return name;
}
export function validatePassword(value: string) {
  const password = value.normalize("NFC"),
    length = [...password].length;
  if (length < 15 || length > 128)
    throw new AuthError(400, "Оберіть парольну фразу від 15 до 128 символів.");
  const compact = password.toLowerCase().replace(/\s/g, "");
  if (
    !compact ||
    /^(.)\1+$/u.test(compact) ||
    new Set([
      "passwordpassword",
      "password123456789",
      "123456789012345",
      "12345678901234567890",
      "qwertyuiopasdfgh",
      "парольпарольпароль",
    ]).has(compact)
  )
    throw new AuthError(
      400,
      "Цей пароль надто простий. Оберіть кілька інших слів.",
    );
  return password;
}
async function derive(password: string, salt: Buffer): Promise<Buffer> {
  if (deriving)
    throw new AuthError(
      429,
      "Зараз обробляється інший вхід. Повторіть за кілька секунд.",
      2,
    );
  deriving = true;
  try {
    return await new Promise<Buffer>((resolve, reject) =>
      scrypt(
        password,
        salt,
        32,
        { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 },
        (e, key) => (e ? reject(e) : resolve(key)),
      ),
    );
  } finally {
    deriving = false;
  }
}
export async function hashPassword(value: string) {
  const password = validatePassword(value),
    salt = randomBytes(16),
    key = await derive(password, salt);
  return `scrypt-v1$${salt.toString("base64url")}$${key.toString("base64url")}`;
}
export async function verifyPassword(value: string, encoded: string) {
  const [version, saltPart, keyPart, ...extra] = encoded.split("$");
  if (version !== "scrypt-v1" || !saltPart || !keyPart || extra.length)
    throw new AuthError(503, "Вхід тимчасово недоступний.");
  const salt = Buffer.from(saltPart, "base64url"),
    key = Buffer.from(keyPart, "base64url");
  if (salt.length !== 16 || key.length !== 32)
    throw new AuthError(503, "Вхід тимчасово недоступний.");
  const password = value.normalize("NFC");
  if ([...password].length > 128) return false;
  return timingSafeEqual(await derive(password, salt), key);
}
