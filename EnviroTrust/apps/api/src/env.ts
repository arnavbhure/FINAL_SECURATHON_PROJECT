import dotenv from 'dotenv';
import path from 'node:path';

// Load environment from .env in repository root and/or apps/api
dotenv.config({ path: path.resolve(process.cwd(), '.env') });
dotenv.config({ path: path.resolve(process.cwd(), 'apps/api/.env') });

export interface ApiEnvironment {
  NODE_ENV: 'development' | 'production' | 'test';
  DEMO_MODE: boolean;
  API_PORT: number;
  API_BASE_URL: string;
  WEB_ORIGIN: string;
  DATABASE_URL: string;
  JWT_SECRET: string;
  JWT_ACCESS_TTL_MINUTES: number;
  JWT_REFRESH_TTL_DAYS: number;
  REFRESH_COOKIE_NAME: string;
  COOKIE_SECURE: boolean;
  COOKIE_SAME_SITE: 'lax' | 'strict' | 'none';
  MAX_FUTURE_SKEW_SECONDS: number;
  MAX_TELEMETRY_AGE_SECONDS: number;
  WITNESS_BASE_URL: string;
  WITNESS_SERVICE_TOKEN: string;
  INTERNAL_AUTH_SECRET: string;
  ML_ENABLED: boolean;
  ML_BASE_URL: string;
  ML_TIMEOUT_MS: number;
  ML_SERVICE_TOKEN: string;
  ML_CONTEXT_WAIT_DEADLINE_SECONDS: number;
}

function parseBoolean(val: string | undefined, defaultVal: boolean): boolean {
  if (val === undefined || val === '') return defaultVal;
  return val.toLowerCase() === 'true' || val === '1';
}

function parseNumber(val: string | undefined, defaultVal: number): number {
  if (val === undefined || val === '') return defaultVal;
  const parsed = Number(val);
  return Number.isNaN(parsed) ? defaultVal : parsed;
}

function validateHttpUrl(urlStr: string, fieldName: string): string {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error(`protocol must be http: or https:`);
    }
    return urlStr.replace(/\/+$/, '');
  } catch (err) {
    throw new Error(`Invalid ${fieldName}: "${urlStr}". Must be a valid HTTP/HTTPS URL (${(err as Error).message})`);
  }
}

/**
 * Validates environment variables safely without printing secret values.
 */
export function loadApiEnvironment(): ApiEnvironment {
  const nodeEnv = (process.env['NODE_ENV'] || 'development') as 'development' | 'production' | 'test';
  const isProd = nodeEnv === 'production';

  const rawMlBaseUrl = process.env['ML_BASE_URL'] || 'http://127.0.0.1:8000';
  const mlBaseUrl = validateHttpUrl(rawMlBaseUrl, 'ML_BASE_URL');

  const env: ApiEnvironment = {
    NODE_ENV: nodeEnv,
    DEMO_MODE: parseBoolean(process.env['DEMO_MODE'], true),
    API_PORT: parseNumber(process.env['API_PORT'], 4000),
    API_BASE_URL: process.env['API_BASE_URL'] || 'http://localhost:4000',
    WEB_ORIGIN: process.env['WEB_ORIGIN'] || 'http://localhost:5173',
    DATABASE_URL: process.env['DATABASE_URL'] || 'postgresql://envirotrust_app:CHANGE_ME@localhost:5432/envirotrust_primary',
    JWT_SECRET: process.env['JWT_SECRET'] || (isProd ? '' : 'development-jwt-secret-not-for-production-min-32-chars-long!'),
    JWT_ACCESS_TTL_MINUTES: parseNumber(process.env['JWT_ACCESS_TTL_MINUTES'], 15),
    JWT_REFRESH_TTL_DAYS: parseNumber(process.env['JWT_REFRESH_TTL_DAYS'], 7),
    REFRESH_COOKIE_NAME: process.env['REFRESH_COOKIE_NAME'] || 'envirotrust_refresh',
    COOKIE_SECURE: parseBoolean(process.env['COOKIE_SECURE'], isProd),
    COOKIE_SAME_SITE: (process.env['COOKIE_SAME_SITE'] || 'lax') as 'lax' | 'strict' | 'none',
    MAX_FUTURE_SKEW_SECONDS: parseNumber(process.env['MAX_FUTURE_SKEW_SECONDS'], 120),
    MAX_TELEMETRY_AGE_SECONDS: parseNumber(process.env['MAX_TELEMETRY_AGE_SECONDS'], 300),
    WITNESS_BASE_URL: process.env['WITNESS_BASE_URL'] || 'http://localhost:4001',
    WITNESS_SERVICE_TOKEN: process.env['WITNESS_SERVICE_TOKEN'] || (isProd ? '' : 'development-witness-service-token'),
    INTERNAL_AUTH_SECRET: process.env['INTERNAL_AUTH_SECRET'] || (isProd ? '' : 'internal_auth_introspection_secret_34567'),
    // Mandatory decision: ML_ENABLED must default to false during development
    ML_ENABLED: parseBoolean(process.env['ML_ENABLED'], false),
    ML_BASE_URL: mlBaseUrl,
    ML_TIMEOUT_MS: parseNumber(process.env['ML_TIMEOUT_MS'], 5000),
    ML_SERVICE_TOKEN: process.env['ML_SERVICE_TOKEN'] || (isProd ? '' : 'development-ml-service-token'),
    ML_CONTEXT_WAIT_DEADLINE_SECONDS: parseNumber(process.env['ML_CONTEXT_WAIT_DEADLINE_SECONDS'], 60),
  };

  if (isProd) {
    if (!process.env['JWT_SECRET'] || process.env['JWT_SECRET'].length < 32) {
      throw new Error('FATAL: JWT_SECRET must be set and at least 32 characters long in production.');
    }
    if (!process.env['DATABASE_URL'] || process.env['DATABASE_URL'].includes('CHANGE_ME')) {
      throw new Error('FATAL: DATABASE_URL must be configured with real credentials in production.');
    }
    if (!process.env['INTERNAL_AUTH_SECRET'] || process.env['INTERNAL_AUTH_SECRET'].length < 32) {
      throw new Error('FATAL: INTERNAL_AUTH_SECRET must be set and at least 32 characters in production.');
    }
    if (env.ML_ENABLED && (!process.env['ML_SERVICE_TOKEN'] || process.env['ML_SERVICE_TOKEN'].length < 16)) {
      throw new Error('FATAL: ML_SERVICE_TOKEN must be set and at least 16 characters in production when ML_ENABLED=true.');
    }
  }

  return env;
}

/**
 * Returns a sanitized summary of configuration safe for logging (no raw secrets).
 */
export function getSanitizedConfigSummary(env: ApiEnvironment): Record<string, string | number | boolean> {
  return {
    NODE_ENV: env.NODE_ENV,
    DEMO_MODE: env.DEMO_MODE,
    API_PORT: env.API_PORT,
    API_BASE_URL: env.API_BASE_URL,
    WEB_ORIGIN: env.WEB_ORIGIN,
    DATABASE_URL: env.DATABASE_URL ? '[CONFIGURED]' : '[MISSING]',
    JWT_SECRET: env.JWT_SECRET ? `[CONFIGURED - ${env.JWT_SECRET.length} chars]` : '[MISSING]',
    JWT_ACCESS_TTL_MINUTES: env.JWT_ACCESS_TTL_MINUTES,
    COOKIE_SECURE: env.COOKIE_SECURE,
    COOKIE_SAME_SITE: env.COOKIE_SAME_SITE,
    MAX_FUTURE_SKEW_SECONDS: env.MAX_FUTURE_SKEW_SECONDS,
    MAX_TELEMETRY_AGE_SECONDS: env.MAX_TELEMETRY_AGE_SECONDS,
    WITNESS_BASE_URL: env.WITNESS_BASE_URL,
    WITNESS_SERVICE_TOKEN: env.WITNESS_SERVICE_TOKEN ? '[CONFIGURED]' : '[MISSING]',
    INTERNAL_AUTH_SECRET: env.INTERNAL_AUTH_SECRET ? '[CONFIGURED]' : '[MISSING]',
    ML_ENABLED: env.ML_ENABLED,
    ML_BASE_URL: env.ML_BASE_URL,
    ML_TIMEOUT_MS: env.ML_TIMEOUT_MS,
    ML_SERVICE_TOKEN: env.ML_SERVICE_TOKEN ? '[CONFIGURED]' : '[MISSING]',
    ML_CONTEXT_WAIT_DEADLINE_SECONDS: env.ML_CONTEXT_WAIT_DEADLINE_SECONDS,
  };
}
