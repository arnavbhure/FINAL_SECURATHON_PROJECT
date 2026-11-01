import net from 'node:net';
import type { Pool } from 'pg';
import type { AttackLabConfig } from './config.js';

export interface SafetyCheck {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
}

export interface SafetyReport {
  ok: boolean;
  checks: SafetyCheck[];
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

function isPrivateIpv4(host: string): boolean {
  if (net.isIPv4(host) === false) return false;
  const [a, b] = host.split('.').map(Number);
  if (a === undefined || b === undefined) return false;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * Attack targets must be local demo services. Private LAN addresses are allowed only when explicitly enabled
 * (two-laptop demo); public hosts are always refused.
 */
export function classifyTargetHost(
  urlStr: string,
  allowPrivateNetworkTargets: boolean
): { ok: boolean; detail: string } {
  let host: string;
  try {
    host = new URL(urlStr).hostname.toLowerCase();
  } catch {
    return { ok: false, detail: 'not a valid URL' };
  }
  if (LOOPBACK_HOSTS.has(host) || host.endsWith('.localhost')) {
    return { ok: true, detail: 'loopback host' };
  }
  if (isPrivateIpv4(host)) {
    return allowPrivateNetworkTargets
      ? { ok: true, detail: 'private LAN host (ATTACK_LAB_ALLOW_PRIVATE_NETWORK_TARGETS=true)' }
      : { ok: false, detail: 'private LAN host refused (set ATTACK_LAB_ALLOW_PRIVATE_NETWORK_TARGETS=true to allow)' };
  }
  return { ok: false, detail: 'non-local host refused' };
}

/**
 * Evaluates every gate that must hold before any scenario touches the services.
 * The server refuses to run scenarios unless all checks pass.
 */
export async function evaluateSafety(
  config: AttackLabConfig,
  primaryPool: Pool,
  witnessPool: Pool
): Promise<SafetyReport> {
  const checks: SafetyCheck[] = [];

  checks.push({
    id: 'demo-mode',
    label: 'DEMO_MODE=true',
    ok: config.demoMode === true,
    detail: config.demoMode ? 'Demo mode enabled' : 'DEMO_MODE is not true',
  });
  checks.push({
    id: 'lab-enabled',
    label: 'ATTACK_LAB_ENABLED=true',
    ok: config.enabled === true,
    detail: config.enabled ? 'Attack Lab explicitly enabled' : 'ATTACK_LAB_ENABLED is not true',
  });
  checks.push({
    id: 'not-production',
    label: 'NODE_ENV is not production',
    ok: config.nodeEnv !== 'production',
    detail: `NODE_ENV=${config.nodeEnv}`,
  });

  const primaryTarget = classifyTargetHost(config.primaryBaseUrl, config.allowPrivateNetworkTargets);
  checks.push({
    id: 'primary-target',
    label: 'Primary API target is a local demo host',
    ok: primaryTarget.ok,
    detail: `${new URL(config.primaryBaseUrl).host}: ${primaryTarget.detail}`,
  });
  const witnessTarget = classifyTargetHost(config.witnessBaseUrl, config.allowPrivateNetworkTargets);
  checks.push({
    id: 'witness-target',
    label: 'Witness target is a local demo host',
    ok: witnessTarget.ok,
    detail: `${new URL(config.witnessBaseUrl).host}: ${witnessTarget.detail}`,
  });

  let primaryDb: string | null = null;
  try {
    const res = await primaryPool.query<{ db: string; is_demo: boolean | null }>(
      `SELECT current_database() AS db,
              (SELECT is_demo FROM sites WHERE site_code = $1) AS is_demo`,
      [config.siteCode]
    );
    primaryDb = res.rows[0]?.db ?? null;
    const isDemoSite = res.rows[0]?.is_demo === true;
    const nameOk = primaryDb === config.expectedPrimaryDbName;
    checks.push({
      id: 'primary-db-identity',
      label: 'Primary database identity',
      ok: nameOk && isDemoSite,
      detail: !nameOk
        ? `connected to "${primaryDb}", expected "${config.expectedPrimaryDbName}"`
        : isDemoSite
          ? `"${primaryDb}" with demo site ${config.siteCode}`
          : `site ${config.siteCode} is missing or not flagged is_demo`,
    });
  } catch (err) {
    checks.push({
      id: 'primary-db-identity',
      label: 'Primary database identity',
      ok: false,
      detail: `cannot query primary database: ${(err as Error).message}`,
    });
  }

  let witnessDb: string | null = null;
  try {
    const res = await witnessPool.query<{ db: string; has_registry: boolean }>(
      `SELECT current_database() AS db,
              to_regclass('public.witness_sensor_keys') IS NOT NULL AS has_registry`
    );
    witnessDb = res.rows[0]?.db ?? null;
    const nameOk = witnessDb === config.expectedWitnessDbName;
    const hasRegistry = res.rows[0]?.has_registry === true;
    checks.push({
      id: 'witness-db-identity',
      label: 'Witness database identity',
      ok: nameOk && hasRegistry,
      detail: !nameOk
        ? `connected to "${witnessDb}", expected "${config.expectedWitnessDbName}"`
        : hasRegistry
          ? `"${witnessDb}" with independent witness key registry`
          : 'witness_sensor_keys table missing (run npm run witness:migrate)',
    });
  } catch (err) {
    checks.push({
      id: 'witness-db-identity',
      label: 'Witness database identity',
      ok: false,
      detail: `cannot query witness database: ${(err as Error).message}`,
    });
  }

  checks.push({
    id: 'separate-databases',
    label: 'Primary and witness use separate databases',
    ok: Boolean(primaryDb && witnessDb && primaryDb !== witnessDb),
    detail: primaryDb && witnessDb ? `${primaryDb} / ${witnessDb}` : 'database identity unknown',
  });

  checks.push({
    id: 'authorized-admins',
    label: 'Explicitly authorized demo administrators configured',
    ok: config.authorizedAdminEmails.length > 0,
    detail: `${config.authorizedAdminEmails.length} authorized demo admin account(s)`,
  });

  return { ok: checks.every((c) => c.ok), checks };
}
