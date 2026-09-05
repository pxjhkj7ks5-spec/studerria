import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import type { Config } from "./config.js";
import type { Store } from "./store.js";
import { hash, secretToken } from "./security.js";
import {
  AuthError,
  normalizeUsername,
  hashPassword,
  verifyPassword,
} from "./password.js";
type Account = {
  user_id: string;
  username: string;
  password_hash: string;
  revision: string;
};
export class Accounts {
  constructor(
    private readonly config: Config,
    private readonly store: Store,
  ) {}
  async gate(token?: string) {
    if (!this.config.configured || !token) return false;
    const { rows } = await this.store.pool.query(
      "SELECT 1 FROM obriy.access_gates WHERE token_hash=$1 AND key_hash=$2 AND expires_at>now()",
      [hash(token), hash(this.config.OBRIY_ADMIN_TOKEN)],
    );
    return Boolean(rows.length);
  }
  async openGate() {
    const token = secretToken();
    await this.store.pool.query(
      "INSERT INTO obriy.access_gates(token_hash,key_hash,expires_at) VALUES($1,$2,now()+interval '30 days')",
      [hash(token), hash(this.config.OBRIY_ADMIN_TOKEN)],
    );
    return token;
  }
  async account(userId: string, c?: PoolClient): Promise<Account | null> {
    const { rows } = await (c ?? this.store.pool).query(
      "SELECT user_id,username,password_hash,revision FROM obriy.accounts WHERE user_id=$1",
      [userId],
    );
    return rows[0] ?? null;
  }
  private async session(c: PoolClient, account: Account) {
    const token = secretToken();
    await c.query(
      "INSERT INTO obriy.sessions(token_hash,user_id,expires_at,auth_revision) VALUES($1,$2,now()+$3*interval '1 hour',$4)",
      [
        hash(token),
        account.user_id,
        this.config.OBRIY_SESSION_HOURS,
        account.revision,
      ],
    );
    await c.query("DELETE FROM obriy.login_attempts WHERE account_key=$1", [
      hash(account.username),
    ]);
    return token;
  }
  private async attempt(username: string) {
    const key = hash(username);
    await this.store.transaction(async (c) => {
      await c.query(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,718031))",
        [key],
      );
      await c.query(
        "DELETE FROM obriy.login_attempts WHERE account_key=$1 AND attempted_at<=now()-interval '5 minutes'",
        [key],
      );
      const { rows } = await c.query(
        "SELECT count(*)::int AS n FROM obriy.login_attempts WHERE account_key=$1",
        [key],
      );
      if (rows[0].n >= 10)
        throw new AuthError(
          429,
          "Забагато спроб для цього логіна. Повторіть через 5 хвилин.",
          300,
        );
      await c.query(
        "INSERT INTO obriy.login_attempts(account_key) VALUES($1)",
        [key],
      );
    });
  }
  async register(
    rawUsername: string,
    password: string,
    legacyUserId: string | null,
  ) {
    const username = normalizeUsername(rawUsername),
      passwordHash = await hashPassword(password);
    try {
      return await this.store.transaction(async (c) => {
        let userId = legacyUserId;
        if (userId) {
          const locked = await c.query(
            "SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE",
            [userId],
          );
          if (!locked.rowCount || (await this.account(userId, c)))
            throw new AuthError(
              409,
              "Акаунт уже налаштовано. Увійдіть за логіном і паролем.",
            );
        } else {
          userId = randomUUID();
          await c.query("INSERT INTO obriy.users(id) VALUES($1)", [userId]);
        }
        const revision = randomUUID();
        await c.query(
          "INSERT INTO obriy.accounts(user_id,username,password_hash,revision) VALUES($1,$2,$3,$4)",
          [userId, username, passwordHash, revision],
        );
        await c.query("DELETE FROM obriy.sessions WHERE user_id=$1", [userId]);
        return this.session(c, {
          user_id: userId,
          username,
          password_hash: passwordHash,
          revision,
        });
      });
    } catch (e) {
      if ((e as { code?: string }).code === "23505")
        throw new AuthError(409, "Цей логін уже зайнятий. Оберіть інший.");
      throw e;
    }
  }
  async login(rawUsername: string, password: string) {
    const username = normalizeUsername(rawUsername);
    await this.attempt(username);
    const { rows } = await this.store.pool.query<Account>(
      "SELECT user_id,username,password_hash,revision FROM obriy.accounts WHERE username=$1",
      [username],
    );
    const account = rows[0];
    // An unknown login still pays the same bounded KDF cost.
    const dummy = `scrypt-v1$${Buffer.alloc(16).toString("base64url")}$${Buffer.alloc(32).toString("base64url")}`;
    const matches = await verifyPassword(
      password,
      account?.password_hash ?? dummy,
    );
    if (!account || !matches)
      throw new AuthError(401, "Логін або пароль не підійшли.");
    return this.store.transaction(async (c) => {
      await c.query("SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE", [
        account.user_id,
      ]);
      const current = await this.account(account.user_id, c);
      if (!current || current.revision !== account.revision)
        throw new AuthError(401, "Доступ було змінено. Увійдіть знову.");
      return this.session(c, current);
    });
  }
  async change(userId: string, currentPassword: string, password: string) {
    const original = await this.account(userId);
    if (!original) throw new AuthError(401, "Увійдіть знову.");
    await this.attempt(original.username);
    if (!(await verifyPassword(currentPassword, original.password_hash)))
      throw new AuthError(401, "Поточний пароль не підійшов.");
    if (currentPassword.normalize("NFC") === password.normalize("NFC"))
      throw new AuthError(400, "Новий пароль має відрізнятися від поточного.");
    const passwordHash = await hashPassword(password);
    return this.store.transaction(async (c) => {
      await c.query("SELECT id FROM obriy.users WHERE id=$1 FOR UPDATE", [
        userId,
      ]);
      const current = await this.account(userId, c);
      if (!current || current.revision !== original.revision)
        throw new AuthError(401, "Доступ було змінено. Увійдіть знову.");
      const revision = randomUUID();
      await c.query(
        "UPDATE obriy.accounts SET password_hash=$2,revision=$3 WHERE user_id=$1",
        [userId, passwordHash, revision],
      );
      await c.query("DELETE FROM obriy.sessions WHERE user_id=$1", [userId]);
      return this.session(c, {
        ...current,
        password_hash: passwordHash,
        revision,
      });
    });
  }
}
