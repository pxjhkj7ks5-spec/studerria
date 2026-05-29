import pg from "pg";
import type { AppConfig } from "./config.js";

export type Db = pg.Pool;

export function createPool(config: AppConfig) {
  const connection = config.database.connectionString
    ? { connectionString: config.database.connectionString }
    : {
        host: config.database.host,
        port: config.database.port,
        user: config.database.user,
        password: config.database.password,
        database: config.database.database,
      };
  return new pg.Pool({
    ...connection,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 8_000,
  });
}

export async function withTransaction<T>(pool: Db, fn: (client: pg.PoolClient) => Promise<T>) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}
