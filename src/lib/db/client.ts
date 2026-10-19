import fs from "fs";
import path from "path";
import { migrate } from "@/lib/db/schema";

export interface Database {
  query<T extends Record<string, unknown> = Record<string, unknown>>(text: string, params?: unknown[]): Promise<T[]>;
  exec(text: string): Promise<void>;
  transaction<T>(fn: (tx: Database) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

function normalize(text: string, params: unknown[] = []): { text: string; params: unknown[] } {
  let index = 0;
  const converted = text.replace(/\?/g, () => {
    index += 1;
    return `$${index}`;
  });
  return {
    text: converted,
    params: params.map((value) => (value === undefined ? null : value)),
  };
}

type Queryable = {
  query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
  exec?(text: string): Promise<unknown>;
};

function wrap(queryable: Queryable, close: () => Promise<void>, begin: () => Promise<Database & { commit(): Promise<void>; rollback(): Promise<void> }>): Database {
  return {
    async query<T extends Record<string, unknown>>(text: string, params: unknown[] = []): Promise<T[]> {
      const statement = normalize(text, params);
      const result = await queryable.query(statement.text, statement.params);
      return result.rows as T[];
    },
    async exec(text: string): Promise<void> {
      if (queryable.exec) {
        await queryable.exec(text);
        return;
      }
      await queryable.query(text);
    },
    async transaction<T>(fn: (tx: Database) => Promise<T>): Promise<T> {
      const tx = await begin();
      try {
        const value = await fn(tx);
        await tx.commit();
        return value;
      } catch (error) {
        await tx.rollback();
        throw error;
      }
    },
    close,
  };
}

async function openPglite(target?: string): Promise<Database> {
  const { PGlite } = await import("@electric-sql/pglite");
  const client = target ? new PGlite(target) : new PGlite();
  await client.waitReady;
  return wrap(
    {
      query: (text, params) => client.query(text, params),
      exec: (text) => client.exec(text),
    },
    () => client.close(),
    async () => {
      await client.query("BEGIN");
      const db = wrap(
        { query: (text, params) => client.query(text, params), exec: (text) => client.exec(text) },
        async () => undefined,
        async () => {
          throw new Error("Nested transactions are not used.");
        },
      );
      return Object.assign(db, {
        commit: () => client.query("COMMIT").then(() => undefined),
        rollback: () => client.query("ROLLBACK").then(() => undefined),
      });
    },
  );
}

async function openPostgres(connectionString: string): Promise<Database> {
  const { Pool } = await import("pg");
  const pool = new Pool({ connectionString, max: 4, statement_timeout: 30000 });
  return wrap(
    { query: (text, params) => pool.query(text, params) },
    () => pool.end(),
    async () => {
      const client = await pool.connect();
      await client.query("BEGIN");
      const db = wrap(
        { query: (text, params) => client.query(text, params) },
        async () => undefined,
        async () => {
          throw new Error("Nested transactions are not used.");
        },
      );
      return Object.assign(db, {
        commit: async () => {
          await client.query("COMMIT");
          client.release();
        },
        rollback: async () => {
          await client.query("ROLLBACK");
          client.release();
        },
      });
    },
  );
}

export async function createDatabase(target: string | ":memory:" = ":memory:"): Promise<Database> {
  if (target === ":memory:") return openPglite();
  if (target.startsWith("postgres://") || target.startsWith("postgresql://")) return openPostgres(target);
  return openPglite(target);
}

const globalForDb = globalThis as unknown as { signaltraceDb?: Promise<Database> };
let chain: Promise<unknown> = Promise.resolve();

export function dataDirectory(): string {
  return path.join(process.cwd(), "data", "pglite");
}

export function getDb(): Promise<Database> {
  if (!globalForDb.signaltraceDb) {
    const target = process.env.DATABASE_URL || dataDirectory();
    if (!process.env.DATABASE_URL) fs.mkdirSync(path.dirname(target), { recursive: true });
    globalForDb.signaltraceDb = createDatabase(target)
      .then(async (db) => {
        await migrate(db);
        return db;
      })
      .catch((error) => {
        globalForDb.signaltraceDb = undefined;
        throw error;
      });
  }
  return globalForDb.signaltraceDb;
}

// PGlite allows one query at a time on its connection. Serialize access.
export function withDb<T>(fn: (db: Database) => Promise<T>): Promise<T> {
  const run = chain.then(() => getDb()).then(fn);
  chain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}
