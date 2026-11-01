import fs from 'node:fs';
import path from 'node:path';
import { createCliEngine } from './demo-lib.js';

/**
 * npm run demo:doctor — checks every prerequisite for the Attack Simulation Lab and prints remediation.
 * Exit code 1 when a blocking check fails. Never prints secrets.
 */
async function main(): Promise<number> {
  const { engine, close } = createCliEngine();
  const cfg = engine.config;
  let blocking = 0;
  const line = (ok: boolean, label: string, detail: string, isBlocking = true) => {
    if (!ok && isBlocking) blocking++;
    console.log(`  ${ok ? '✓' : isBlocking ? '✗' : '!'} ${label.padEnd(46)} ${detail}`);
  };

  try {
    console.log('EnviroTrust Attack Simulation Lab — demo doctor (DEMO ENVIRONMENT)\n');

    console.log('Safety gates');
    const safety = await engine.safety();
    for (const c of safety.checks) line(c.ok, c.label, c.detail);

    console.log('\nServices');
    const status = await engine.status();
    line(status.services.primary.reachable, `Primary API ${cfg.primaryBaseUrl}`, status.services.primary.detail);
    line(status.services.witness.reachable, `Witness ${cfg.witnessBaseUrl}`, `${status.services.witness.detail} ${status.services.witness.displayName ?? ''}`);
    line(
      status.services.ml.reachable,
      `ML service ${cfg.mlBaseUrl}`,
      status.services.ml.reachable
        ? `reachable, model ${status.services.ml.modelVersion ?? 'unknown'} (${status.services.ml.modelMode ?? 'mode n/a'}), ready=${String(status.services.ml.ready)}`
        : `${status.services.ml.detail} — scenario F will report ML_UNAVAILABLE`,
      false
    );
    line(status.services.ml.enabledOnPrimary, 'Primary ML_ENABLED', status.services.ml.enabledOnPrimary ? 'true' : 'false — scenario F will report ML_NOT_ENABLED', false);

    const routes = await fetch(`${cfg.primaryBaseUrl}/api/v1/demo/attack-lab/scenarios`).catch(() => null);
    line(
      routes?.status === 401,
      'Attack Lab routes mounted on running API',
      routes ? (routes.status === 401 ? 'mounted (auth required)' : routes.status === 404 ? 'NOT mounted — restart API with DEMO_MODE=true ATTACK_LAB_ENABLED=true' : `HTTP ${routes.status}`) : 'API unreachable'
    );

    console.log('\nDatabase state');
    const mig = await engine.primaryPool.query<{ ok: boolean }>("SELECT to_regclass('public.attack_lab_runs') IS NOT NULL AS ok");
    line(mig.rows[0]?.ok === true, 'Primary migration 008 (attack_lab_runs)', mig.rows[0]?.ok ? 'applied' : 'missing — npm run db:migrate');
    const users = await engine.primaryPool.query<{ n: string }>(
      "SELECT count(*)::text AS n FROM users WHERE email = ANY($1) AND status = 'ACTIVE'",
      [cfg.authorizedAdminEmails]
    );
    line(Number(users.rows[0]?.n || 0) > 0, 'Authorized demo admin account exists', `${users.rows[0]?.n ?? 0} of ${cfg.authorizedAdminEmails.length} — npm run users:seed`);
    const recent = await engine.primaryPool.query<{ n: string }>("SELECT count(*)::text AS n FROM telemetry_readings WHERE received_at > now() - interval '60 seconds'");
    line(Number(recent.rows[0]?.n || 0) > 0, 'Live sensor stream activity (last 60 s)', `${recent.rows[0]?.n ?? 0} reading(s) — start npm run stream:all`, false);

    console.log('\nKey material (presence only; contents never printed)');
    const files: Array<[string, string]> = [
      ['COD-OUT-001 sensor key', path.join(cfg.secretsDir, 'sensor-keys', 'COD-OUT-001', 'private.pem')],
      ['PH-OUT-001 sensor key', path.join(cfg.secretsDir, 'sensor-keys', 'PH-OUT-001', 'private.pem')],
      ['OPS-001 operations key', path.join(cfg.secretsDir, 'ops-keys', 'OPS-001', 'private.pem')],
      ['Witness public key (trust anchor)', path.join(cfg.secretsDir, 'witness-keys', 'public.pem')],
    ];
    for (const [label, file] of files) line(fs.existsSync(file), label, fs.existsSync(file) ? 'present' : 'missing — npm run keys:provision / witness:keys:provision');
    for (const [code, s] of Object.entries(status.demoIdentities)) {
      line(s.ready, `Demo identity ${code}`, s.ready ? `${s.keyId} registered in both registries` : 'not provisioned — npm run demo:provision');
    }

    console.log(blocking === 0 ? '\nReady: all blocking checks passed.' : `\n${blocking} blocking check(s) failed.`);
    return blocking === 0 ? 0 : 1;
  } finally {
    await close();
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[demo:doctor] fatal:', (err as Error).message);
    process.exit(1);
  });
