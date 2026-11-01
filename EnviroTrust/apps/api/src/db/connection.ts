import pg from 'pg';
import type { Pool } from 'pg';
import dotenv from 'dotenv';

// Load environment configuration
dotenv.config();

let poolInstance: Pool | null = null;

export function getDbPool(customConnectionString?: string): Pool {
  if (poolInstance && !customConnectionString) {
    return poolInstance;
  }

  const connectionString =
    customConnectionString ||
    process.env['DATABASE_URL'] ||
    'postgresql://envirotrust_app:envirotrust_app_local_pw@localhost:5432/envirotrust_primary';

  const pool = new pg.Pool({
    connectionString,
    max: 20,
    idleTimeoutMillis: process.env['NODE_ENV'] === 'test' ? 500 : 10000,
    connectionTimeoutMillis: 5000,
  });

  pool.on('error', (err: Error) => {
    console.error('PostgreSQL pool error:', err.message);
  });

  if (!customConnectionString) {
    poolInstance = pool;
  }

  return pool;
}

export async function closeDbPool(): Promise<void> {
  if (poolInstance) {
    await poolInstance.end();
    poolInstance = null;
  }
}
