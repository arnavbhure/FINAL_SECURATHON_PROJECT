import dotenv from 'dotenv';
import path from 'node:path';
import fs from 'node:fs';

function findWitnessKeyDir(): string {
  const envVal = process.env['WITNESS_KEY_DIR'];
  if (envVal) {
    const directPath = path.resolve(process.cwd(), envVal);
    if (fs.existsSync(path.join(directPath, 'public.pem'))) {
      return directPath;
    }
    const upPath = path.resolve(process.cwd(), '../../', envVal);
    if (fs.existsSync(path.join(upPath, 'public.pem'))) {
      return upPath;
    }
  }
  const candidates = [
    path.resolve(process.cwd(), 'local-secrets/witness-keys'),
    path.resolve(process.cwd(), '../../local-secrets/witness-keys'),
    path.resolve(process.cwd(), '../local-secrets/witness-keys'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'public.pem'))) return c;
  }
  return path.resolve(process.cwd(), 'local-secrets/witness-keys');
}

// Load environment from .env in apps/witness or repository root
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

export interface WitnessEnvironment {
  NODE_ENV: 'development' | 'production' | 'test';
  WEB_ORIGIN: string;
  WITNESS_PORT: number;
  WITNESS_BASE_URL: string;
  WITNESS_DATABASE_URL: string;
  WITNESS_ID: string;
  WITNESS_DISPLAY_NAME: string;
  WITNESS_CHECKPOINT_EVERY: number;
  WITNESS_KEY_DIR: string;
  WITNESS_SERVICE_TOKEN: string;
  WITNESS_INGESTION_TOKEN: string;
  PRIMARY_API_URL: string;
  INTERNAL_AUTH_SECRET: string;
  INTROSPECTION_TIMEOUT_MS: number;
  JWT_SECRET: string;
  MAX_FUTURE_SKEW_SECONDS: number;
  MAX_TELEMETRY_AGE_SECONDS: number;
}

function parseNumber(val: string | undefined, defaultVal: number): number {
  if (val === undefined || val === '') return defaultVal;
  const parsed = Number(val);
  return Number.isNaN(parsed) ? defaultVal : parsed;
}

/**
 * Validates witness environment variables safely without printing secret values.
 */
export function loadWitnessEnvironment(): WitnessEnvironment {
  const nodeEnv = (process.env['NODE_ENV'] || 'development') as 'development' | 'production' | 'test';
  const isProd = nodeEnv === 'production';

  const env: WitnessEnvironment = {
    NODE_ENV: nodeEnv,
    WEB_ORIGIN: process.env['WEB_ORIGIN'] || 'http://localhost:5173',
    WITNESS_PORT: parseNumber(process.env['WITNESS_PORT'], 4001),
    WITNESS_BASE_URL: process.env['WITNESS_BASE_URL'] || 'http://localhost:4001',
    WITNESS_DATABASE_URL:
      process.env['WITNESS_DATABASE_URL'] ||
      'postgresql://envirotrust_witness:envirotrust_witness_local_pw@localhost:5432/envirotrust_witness',
    WITNESS_ID: process.env['WITNESS_ID'] || 'WITNESS-001',
    WITNESS_DISPLAY_NAME: process.env['WITNESS_DISPLAY_NAME'] || 'Simulated Independent Witness',
    WITNESS_CHECKPOINT_EVERY: parseNumber(process.env['WITNESS_CHECKPOINT_EVERY'], 10),
    WITNESS_KEY_DIR: findWitnessKeyDir(),
    WITNESS_SERVICE_TOKEN:
      process.env['WITNESS_SERVICE_TOKEN'] || (isProd ? '' : 'development-witness-service-token'),
    WITNESS_INGESTION_TOKEN:
      process.env['WITNESS_INGESTION_TOKEN'] || 'witness_ingestion_internal_token_secret_98765',
    PRIMARY_API_URL: process.env['PRIMARY_API_URL'] || process.env['API_BASE_URL'] || 'http://localhost:4000',
    INTERNAL_AUTH_SECRET:
      process.env['INTERNAL_AUTH_SECRET'] || (isProd ? '' : 'internal_auth_introspection_secret_34567'),
    INTROSPECTION_TIMEOUT_MS: parseNumber(process.env['INTROSPECTION_TIMEOUT_MS'], 2500),
    JWT_SECRET: process.env['JWT_SECRET'] || (isProd ? '' : 'development-jwt-secret-not-for-production-min-32-chars-long!'),
    MAX_FUTURE_SKEW_SECONDS: parseNumber(process.env['MAX_FUTURE_SKEW_SECONDS'], 120),
    MAX_TELEMETRY_AGE_SECONDS: parseNumber(process.env['MAX_TELEMETRY_AGE_SECONDS'], 300),
  };

  if (isProd) {
    if (!process.env['WITNESS_SERVICE_TOKEN'] || process.env['WITNESS_SERVICE_TOKEN'].length < 32) {
      throw new Error('FATAL: WITNESS_SERVICE_TOKEN must be set and at least 32 characters in production.');
    }
    if (!process.env['INTERNAL_AUTH_SECRET'] || process.env['INTERNAL_AUTH_SECRET'].length < 32) {
      throw new Error('FATAL: INTERNAL_AUTH_SECRET must be set and at least 32 characters in production.');
    }
  }

  return env;
}

/**
 * Returns a sanitized summary of configuration safe for logging (no raw secrets).
 */
export function getSanitizedWitnessConfigSummary(env: WitnessEnvironment): Record<string, string | number | boolean> {
  return {
    NODE_ENV: env.NODE_ENV,
    WITNESS_PORT: env.WITNESS_PORT,
    WITNESS_BASE_URL: env.WITNESS_BASE_URL,
    WITNESS_DATABASE_URL: env.WITNESS_DATABASE_URL ? '[CONFIGURED]' : '[MISSING]',
    WITNESS_ID: env.WITNESS_ID,
    WITNESS_DISPLAY_NAME: env.WITNESS_DISPLAY_NAME,
    WITNESS_CHECKPOINT_EVERY: env.WITNESS_CHECKPOINT_EVERY,
    WITNESS_KEY_DIR: env.WITNESS_KEY_DIR,
    WITNESS_SERVICE_TOKEN: env.WITNESS_SERVICE_TOKEN ? '[CONFIGURED]' : '[MISSING]',
    PRIMARY_API_URL: env.PRIMARY_API_URL,
    INTERNAL_AUTH_SECRET: env.INTERNAL_AUTH_SECRET ? '[CONFIGURED]' : '[MISSING]',
  };
}
