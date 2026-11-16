import { drizzle, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import { Pool } from "pg";
import * as schema from "./schema";

export type DB = NodePgDatabase<typeof schema>;
export type Tx = Parameters<Parameters<DB["transaction"]>[0]>[0];

const globalForDb = globalThis as unknown as { ruyaPool?: Pool; ruyaDb?: DB };

function pool(): Pool {
  if (!globalForDb.ruyaPool) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is required");
    globalForDb.ruyaPool = new Pool({ connectionString: url, max: 10 });
  }
  return globalForDb.ruyaPool;
}

// Lazy so importing this module (e.g. during `next build`) never needs a DB connection.
export const db: DB = new Proxy({} as DB, {
  get(_t, prop) {
    globalForDb.ruyaDb ??= drizzle(pool(), { schema });
    return Reflect.get(globalForDb.ruyaDb, prop, globalForDb.ruyaDb);
  },
});

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (v: unknown): v is string => typeof v === "string" && UUID_RE.test(v);

/**
 * Runs fn in a transaction whose RLS tenant is orgId (SET LOCAL app.org_id).
 * Pass null for pre-tenant work (sign-in, org listing); tenant tables then return no rows.
 */
export async function withOrg<T>(orgId: string | null, fn: (tx: Tx) => Promise<T>): Promise<T> {
  if (orgId !== null && !isUuid(orgId)) throw new Error("withOrg: invalid org id");
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('app.org_id', ${orgId ?? ""}, true)`);
    return fn(tx);
  });
}

export async function closeDb() {
  await globalForDb.ruyaPool?.end();
  globalForDb.ruyaPool = undefined;
  globalForDb.ruyaDb = undefined;
}
