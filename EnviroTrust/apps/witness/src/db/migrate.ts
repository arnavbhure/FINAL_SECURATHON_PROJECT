import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Pool } from 'pg';
import { getWitnessDbPool } from './connection.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function getMigrationsDir(): string {
  const possiblePaths = [
    path.resolve(__dirname, '../../migrations'),
    path.resolve(__dirname, '../migrations'),
    path.resolve(process.cwd(), 'apps/witness/migrations'),
    path.resolve(process.cwd(), 'migrations'),
  ];
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  throw new Error('Witness migrations directory not found');
}

export async function runWitnessMigrations(customPool?: Pool): Promise<string[]> {
  const pool = customPool || getWitnessDbPool();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Create schema_migrations table if not exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // Fetch already applied migrations
    const res = await client.query<{ version: string }>(
      'SELECT version FROM schema_migrations ORDER BY version ASC'
    );
    const appliedVersions = new Set(res.rows.map((r: { version: string }) => r.version));

    const migrationsDir = getMigrationsDir();
    const files = fs
      .readdirSync(migrationsDir)
      .filter((f) => f.endsWith('.sql'))
      .sort();

    const newlyApplied: string[] = [];

    for (const file of files) {
      const version = file.split('_')[0] || file;
      if (!appliedVersions.has(version)) {
        const filePath = path.join(migrationsDir, file);
        const sql = fs.readFileSync(filePath, 'utf-8');

        console.log(`[WITNESS_MIGRATION] Applying ${file}...`);
        await client.query(sql);
        await client.query(
          'INSERT INTO schema_migrations (version, name) VALUES ($1, $2)',
          [version, file]
        );
        newlyApplied.push(file);
      }
    }

    await client.query('COMMIT');
    console.log(`[WITNESS_MIGRATION] Done. Applied ${newlyApplied.length} new migrations.`);
    return newlyApplied;
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[WITNESS_MIGRATION] Error running migrations:', (err as Error).message);
    throw err;
  } finally {
    client.release();
  }
}

// Direct CLI invocation
if (process.argv[1] && process.argv[1].endsWith('migrate.ts')) {
  runWitnessMigrations()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}

