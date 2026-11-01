import pg from 'pg';
import type { Pool } from 'pg';
import dotenv from 'dotenv';

// Load environment configuration
dotenv.config();

let poolInstance: Pool | null = null;

export function getWitnessDbPool(customConnectionString?: string): Pool {
  if (poolInstance && !customConnectionString) {
    return poolInstance;
  }

  const connectionString =
    customConnectionString ||
    process.env['WITNESS_DATABASE_URL'] ||
    'postgresql://envirotrust_witness:envirotrust_witness_local_pw@localhost:5432/envirotrust_witness';

  const pool = new pg.Pool({
    connectionString,
    max: 15,
    idleTimeoutMillis: process.env['NODE_ENV'] === 'test' ? 500 : 10000,
    connectionTimeoutMillis: 5000,
  });

  pool.on('error', (err: Error) => {
    console.error('[WITNESS_DB] Pool error:', err.message);
  });

  if (!customConnectionString) {
    poolInstance = pool;
  }

  return pool;
}

export async function closeWitnessDbPool(): Promise<void> {
  if (poolInstance) {
    await poolInstance.end();
    poolInstance = null;
  }
}
