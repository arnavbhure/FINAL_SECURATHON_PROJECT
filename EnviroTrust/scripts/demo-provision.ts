import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { generateEd25519KeyPair, calculatePublicKeyFingerprint, type PublicKeyManifest } from '@envirotrust/crypto';
import { registerKeysFromManifest } from '../apps/api/src/services/key-registry.service.js';
import { registerWitnessKeys } from '../apps/witness/src/services/witness-key-registry.service.js';
import { LAB_COMPROMISED_SENSOR_CODE, LAB_SENSOR_CODE } from '../apps/api/src/attack-lab/index.js';
import { createCliEngine } from './demo-lib.js';

/**
 * npm run demo:provision
 *
 * Creates the dedicated Attack Lab demo identities (never the production sensor keys):
 *   LAB-COD-901 / LAB-COD-901-KEY-V1               — Attack Lab demo sensor (scenarios G, H, I)
 *   LAB-COD-902 / LAB-COD-902-COMPROMISED-KEY-V1   — SIMULATED COMPROMISED KEY (scenario F)
 * Private keys are written only to local-secrets/attack-lab/identities (gitignored, mode 0600).
 * Public keys are registered independently in the Primary and Witness registries.
 */
const IDENTITIES = [
  { sensorCode: LAB_SENSOR_CODE, keyId: 'LAB-COD-901-KEY-V1', purpose: 'Attack Lab demo sensor (genuine lab traffic, heartbeat and outage scenarios)' },
  { sensorCode: LAB_COMPROMISED_SENSOR_CODE, keyId: 'LAB-COD-902-COMPROMISED-KEY-V1', purpose: 'SIMULATED COMPROMISED KEY (insider scenario F)' },
];

async function main(): Promise<number> {
  const { engine, close } = createCliEngine();
  const witnessPool = new pg.Pool({ connectionString: engine.config.witnessDatabaseUrl, max: 2 });
  try {
    const safety = await engine.safety();
    if (!safety.ok) {
      console.error('Refusing to provision demo identities — safety checks failed:');
      for (const c of safety.checks.filter((x) => !x.ok)) console.error(`  ✗ ${c.label}: ${c.detail}`);
      return 1;
    }

    const pool = engine.primaryPool;
    const stationRes = await pool.query<{ id: string }>(
      `SELECT st.id FROM monitoring_stations st JOIN sites si ON si.id = st.site_id
       WHERE si.site_code = $1 AND st.station_code = $2`,
      [engine.config.siteCode, engine.config.stationCode]
    );
    const stationId = stationRes.rows[0]?.id;
    if (!stationId) {
      console.error(`Station ${engine.config.stationCode} not found — run npm run db:migrate first.`);
      return 1;
    }

    const manifest: PublicKeyManifest = { schemaVersion: 1, generatedAt: new Date().toISOString(), keys: [] };
    for (const id of IDENTITIES) {
      const dir = path.join(engine.config.labSecretsDir, 'identities', id.sensorCode);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      const privPath = path.join(dir, 'private.pem');
      const pubPath = path.join(dir, 'public.pem');
      const metaPath = path.join(dir, 'metadata.json');
      if (!fs.existsSync(privPath) || !fs.existsSync(pubPath)) {
        const kp = generateEd25519KeyPair();
        fs.writeFileSync(privPath, kp.privateKeyPem, { encoding: 'utf-8', mode: 0o600 });
        fs.writeFileSync(pubPath, kp.publicKeyPem, { encoding: 'utf-8', mode: 0o644 });
        console.log(`Generated key pair for ${id.sensorCode}`);
      }
      const publicKeyPem = fs.readFileSync(pubPath, 'utf-8');
      const fingerprint = calculatePublicKeyFingerprint(publicKeyPem);
      fs.writeFileSync(
        metaPath,
        JSON.stringify({ keyId: id.keyId, sensorId: id.sensorCode, demoIdentity: true, purpose: id.purpose, publicKeyFingerprint: fingerprint }, null, 2),
        'utf-8'
      );

      const existing = await pool.query<{ is_demo_identity: boolean }>('SELECT is_demo_identity FROM sensors WHERE sensor_code = $1', [id.sensorCode]);
      if (existing.rows[0] && existing.rows[0].is_demo_identity !== true) {
        console.error(`Refusing: sensor ${id.sensorCode} already exists and is not a demo identity.`);
        return 1;
      }
      await pool.query(
        `INSERT INTO sensors (sensor_code, station_id, parameter, unit, expected_interval_seconds, status, is_demo_identity)
         VALUES ($1, $2, 'COD', 'mg/L', 10, 'INACTIVE', TRUE)
         ON CONFLICT (sensor_code) DO NOTHING`,
        [id.sensorCode, stationId]
      );

      manifest.keys.push({
        keyId: id.keyId,
        identityType: 'SENSOR',
        identityId: id.sensorCode,
        siteId: engine.config.siteCode,
        stationId: engine.config.stationCode,
        parameter: 'COD',
        algorithm: 'Ed25519',
        publicKeyPem: publicKeyPem.trim(),
        publicKeyFingerprint: fingerprint,
        createdAt: new Date().toISOString(),
        status: 'ACTIVE',
      });
      console.log(`  ${id.sensorCode.padEnd(12)} ${id.keyId.padEnd(32)} fingerprint ${fingerprint}`);
    }

    const manifestPath = path.join(engine.config.labSecretsDir, 'public-key-manifest.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');
    const p = await registerKeysFromManifest(manifestPath, pool);
    const w = await registerWitnessKeys(manifestPath, witnessPool);
    console.log(`Primary registry: ${p.registeredDevices} demo key(s) ACTIVE. Witness registry: ${w.registeredSensorKeys} demo key(s) ACTIVE.`);
    console.log('Demo identity sensors are INACTIVE outside Attack Lab runs (no availability alerts while idle).');
    return 0;
  } finally {
    await witnessPool.end();
    await close();
  }
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error('[demo:provision] fatal:', (err as Error).message);
    process.exit(1);
  });
