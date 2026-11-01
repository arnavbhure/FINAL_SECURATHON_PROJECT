import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ApiEnvironment } from '../env.js';

/**
 * Attack Lab configuration. Every target URL and identity comes from server-side configuration;
 * nothing here can be supplied by a browser request.
 */
export interface AttackLabConfig {
  enabled: boolean;
  demoMode: boolean;
  nodeEnv: string;
  primaryBaseUrl: string;
  witnessBaseUrl: string;
  witnessIngestionToken: string;
  witnessServiceToken: string;
  witnessDatabaseUrl: string;
  expectedPrimaryDbName: string;
  expectedWitnessDbName: string;
  allowPrivateNetworkTargets: boolean;
  siteCode: string;
  stationCode: string;
  repoRoot: string;
  secretsDir: string;
  labSecretsDir: string;
  workDir: string;
  authorizedAdminEmails: string[];
  compromisedCodValue: string;
  trustedWitnessFingerprint: string | null;
  mlWaitSeconds: number;
  mlBaseUrl: string;
  mlTimeoutMs: number;
  mlServiceToken: string;
}

export const LAB_SENSOR_CODE = 'LAB-COD-901';
export const LAB_COMPROMISED_SENSOR_CODE = 'LAB-COD-902';
export const DEFAULT_AUTHORIZED_DEMO_ADMIN = 'admin@envirotrust.local';

function parseBoolean(val: string | undefined, defaultVal: boolean): boolean {
  if (val === undefined || val === '') return defaultVal;
  return val.toLowerCase() === 'true' || val === '1';
}

/** Walks up from this module to the monorepo root (the package.json that declares workspaces). */
export function findRepoRoot(startDir?: string): string {
  let dir = startDir || path.dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 8; i++) {
    const pkgPath = path.join(dir, 'package.json');
    if (fs.existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')) as { workspaces?: unknown };
        if (Array.isArray(pkg.workspaces)) return dir;
      } catch {
        // keep walking
      }
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return process.cwd();
}

/** True only when every startup gate for mounting the demo-only routes is satisfied. */
export function isAttackLabEnabled(env: Pick<ApiEnvironment, 'DEMO_MODE' | 'NODE_ENV'>): boolean {
  return (
    env.DEMO_MODE === true &&
    env.NODE_ENV !== 'production' &&
    parseBoolean(process.env['ATTACK_LAB_ENABLED'], false)
  );
}

export function loadAttackLabConfig(env: ApiEnvironment): AttackLabConfig {
  const repoRoot = findRepoRoot();
  const secretsDir = path.resolve(repoRoot, 'local-secrets');
  const adminList = (process.env['ATTACK_LAB_AUTHORIZED_ADMINS'] || DEFAULT_AUTHORIZED_DEMO_ADMIN)
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

  return {
    enabled: parseBoolean(process.env['ATTACK_LAB_ENABLED'], false),
    demoMode: env.DEMO_MODE,
    nodeEnv: env.NODE_ENV,
    primaryBaseUrl: (process.env['ATTACK_LAB_PRIMARY_URL'] || env.API_BASE_URL).replace(/\/+$/, ''),
    witnessBaseUrl: env.WITNESS_BASE_URL.replace(/\/+$/, ''),
    witnessIngestionToken:
      process.env['WITNESS_INGESTION_TOKEN'] || 'witness_ingestion_internal_token_secret_98765',
    witnessServiceToken: env.WITNESS_SERVICE_TOKEN,
    witnessDatabaseUrl:
      process.env['WITNESS_DATABASE_URL'] ||
      'postgresql://envirotrust_witness:envirotrust_witness_local_pw@localhost:5432/envirotrust_witness',
    expectedPrimaryDbName: process.env['ATTACK_LAB_EXPECTED_PRIMARY_DB'] || 'envirotrust_primary',
    expectedWitnessDbName: process.env['ATTACK_LAB_EXPECTED_WITNESS_DB'] || 'envirotrust_witness',
    allowPrivateNetworkTargets: parseBoolean(process.env['ATTACK_LAB_ALLOW_PRIVATE_NETWORK_TARGETS'], false),
    siteCode: 'PLANT-001',
    stationCode: 'ETP-OUTLET-001',
    repoRoot,
    secretsDir,
    labSecretsDir: path.join(secretsDir, 'attack-lab'),
    workDir: process.env['ATTACK_LAB_WORK_DIR'] || path.join(os.tmpdir(), 'envirotrust-attack-lab'),
    authorizedAdminEmails: adminList,
    compromisedCodValue: process.env['ATTACK_LAB_COMPROMISED_COD_VALUE'] || '18.40',
    trustedWitnessFingerprint: process.env['ATTACK_LAB_TRUSTED_WITNESS_FINGERPRINT'] || null,
    mlWaitSeconds: Number(process.env['ATTACK_LAB_ML_WAIT_SECONDS']) || 75,
    mlBaseUrl: env.ML_BASE_URL,
    mlTimeoutMs: env.ML_TIMEOUT_MS,
    mlServiceToken: env.ML_SERVICE_TOKEN,
  };
}

export function isAuthorizedDemoAdmin(
  config: Pick<AttackLabConfig, 'authorizedAdminEmails'>,
  user: { role: string; email: string } | undefined
): boolean {
  if (!user || user.role !== 'PLATFORM_ADMIN') return false;
  return config.authorizedAdminEmails.includes(user.email.toLowerCase());
}
