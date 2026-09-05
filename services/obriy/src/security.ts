import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
export const secretToken = () => randomBytes(32).toString("base64url");
export const hash = (text: string) =>
  createHash("sha256").update(text).digest("hex");
export function equalSecret(a: string, b: string): boolean {
  return (
    Boolean(a && b) &&
    timingSafeEqual(
      createHash("sha256").update(a).digest(),
      createHash("sha256").update(b).digest(),
    )
  );
}
export class Vault {
  constructor(private readonly key: string) {}
  encrypt(value: unknown, context: string): string {
    if (!/^[a-f0-9]{64}$/i.test(this.key))
      throw new Error("Encryption unavailable");
    const iv = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", Buffer.from(this.key, "hex"), iv);
    cipher.setAAD(Buffer.from(context));
    const data = Buffer.concat([
      cipher.update(JSON.stringify(value), "utf8"),
      cipher.final(),
    ]);
    return [
      "v1",
      iv.toString("base64url"),
      cipher.getAuthTag().toString("base64url"),
      data.toString("base64url"),
    ].join(".");
  }
  decrypt<T>(value: string, context: string): T {
    try {
      const [v, iv, tag, data, ...extra] = value.split(".");
      if (v !== "v1" || !iv || !tag || !data || extra.length) throw new Error();
      const decipher = createDecipheriv(
        "aes-256-gcm",
        Buffer.from(this.key, "hex"),
        Buffer.from(iv, "base64url"),
      );
      decipher.setAAD(Buffer.from(context));
      decipher.setAuthTag(Buffer.from(tag, "base64url"));
      return JSON.parse(
        Buffer.concat([
          decipher.update(Buffer.from(data, "base64url")),
          decipher.final(),
        ]).toString("utf8"),
      ) as T;
    } catch {
      throw new Error("Protected data cannot be decrypted");
    }
  }
}
export function logEvent(
  event: string,
  fields: Record<string, number | boolean | string> = {},
) {
  // Callers pass allowlisted event codes/counts only; never an Error or external body.
  process.stdout.write(
    JSON.stringify({ time: new Date().toISOString(), event, ...fields }) + "\n",
  );
}
