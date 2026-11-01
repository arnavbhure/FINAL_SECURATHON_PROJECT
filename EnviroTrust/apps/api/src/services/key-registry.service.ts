import fs from 'node:fs';
import path from 'node:path';
import type { Pool } from 'pg';
import { computePublicKeyFingerprint } from '@envirotrust/crypto';
import { getDbPool } from '../db/connection.js';

interface ManifestKey {
  keyId: string;
  identityType: 'SENSOR' | 'OPERATIONS_SOURCE';
  identityId: string;
  siteId: string;
  stationId: string;
  parameter?: string | null;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  publicKeyFingerprint: string;
  createdAt: string;
  status: 'ACTIVE';
}

interface Manifest {
  schemaVersion: number;
  generatedAt: string;
  keys: ManifestKey[];
}

export function findManifestPath(overridePath?: string): string {
  if (overridePath && fs.existsSync(overridePath)) {
    return overridePath;
  }
  const possiblePaths = [
    overridePath,
    path.resolve(process.cwd(), 'local-secrets/provisioning/public-key-manifest.json'),
    path.resolve(process.cwd(), '../../local-secrets/provisioning/public-key-manifest.json'),
    path.resolve(process.cwd(), '../local-secrets/provisioning/public-key-manifest.json'),
  ].filter(Boolean) as string[];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  return path.resolve(process.cwd(), 'local-secrets/provisioning/public-key-manifest.json');
}

export async function registerKeysFromManifest(
  manifestPath?: string,
  customPool?: Pool
): Promise<{
  registeredDevices: number;
  registeredOpsSources: number;
}> {
  const filePath = findManifestPath(manifestPath);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Manifest file not found: ${filePath}`);
  }

  const raw = fs.readFileSync(filePath, 'utf-8');
  const manifest = JSON.parse(raw) as Manifest;

  if (!manifest.keys || !Array.isArray(manifest.keys)) {
    throw new Error('Invalid manifest: missing keys array');
  }

  const pool = customPool || getDbPool();
  const client = await pool.connect();
  let registeredDevices = 0;
  let registeredOpsSources = 0;

  try {
    await client.query('BEGIN');

    for (const key of manifest.keys) {
      if (key.algorithm !== 'Ed25519') {
        throw new Error(`Unsupported algorithm ${key.algorithm} for key ${key.keyId}`);
      }

      const computedFingerprint = computePublicKeyFingerprint(key.publicKeyPem);
      if (computedFingerprint !== key.publicKeyFingerprint) {
        throw new Error(
          `Fingerprint mismatch for ${key.keyId}! Manifest: ${key.publicKeyFingerprint}, Computed: ${computedFingerprint}`
        );
      }

      if (key.identityType === 'SENSOR') {
        const sensorRes = await client.query<{ id: string; parameter: string }>(
          'SELECT id, parameter FROM sensors WHERE sensor_code = $1',
          [key.identityId]
        );
        if (sensorRes.rows.length === 0 || !sensorRes.rows[0]) {
          throw new Error(`Sensor not found in database: ${key.identityId}`);
        }
        const sensor = sensorRes.rows[0];
        if (key.parameter && sensor.parameter !== key.parameter) {
          throw new Error(
            `Parameter mismatch for sensor ${key.identityId}: DB has ${sensor.parameter}, key claims ${key.parameter}`
          );
        }

        // Check if key already exists
        const existingKeyRes = await client.query<{
          status: string;
          sensor_id: string;
          fingerprint_sha256: string;
        }>(
          'SELECT status, sensor_id, fingerprint_sha256 FROM device_keys WHERE key_id = $1',
          [key.keyId]
        );

        if (existingKeyRes.rows.length > 0 && existingKeyRes.rows[0]) {
          const row = existingKeyRes.rows[0];
          // Disallow changing sensor binding
          if (row.sensor_id !== sensor.id) {
            throw new Error(
              `Cannot rebind key ${key.keyId} to different sensor: existing=${row.sensor_id}, attempted=${sensor.id}`
            );
          }
          // Disallow overwriting public key material
          if (row.fingerprint_sha256 !== computedFingerprint) {
            throw new Error(
              `Cannot overwrite key material for key ${key.keyId} with differing fingerprint`
            );
          }
          // Disallow reactivating revoked key
          if (row.status === 'REVOKED') {
            continue;
          }
          registeredDevices++;
          continue;
        }

        await client.query(
          `INSERT INTO device_keys (
             key_id, sensor_id, algorithm, public_key_pem, fingerprint_sha256, status, valid_from
           )
           VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6)`,
          [
            key.keyId,
            sensor.id,
            key.algorithm,
            key.publicKeyPem,
            computedFingerprint,
            key.createdAt || new Date().toISOString(),
          ]
        );
        registeredDevices++;
      } else if (key.identityType === 'OPERATIONS_SOURCE') {
        const siteRes = await client.query<{ id: string }>(
          'SELECT id FROM sites WHERE site_code = $1',
          [key.siteId]
        );
        if (siteRes.rows.length === 0 || !siteRes.rows[0]) {
          throw new Error(`Site not found in database: ${key.siteId}`);
        }
        const site = siteRes.rows[0];

        const stationRes = await client.query<{ id: string }>(
          'SELECT id FROM monitoring_stations WHERE site_id = $1 AND station_code = $2',
          [site.id, key.stationId]
        );
        if (stationRes.rows.length === 0 || !stationRes.rows[0]) {
          throw new Error(`Station not found in database: ${key.stationId}`);
        }
        const station = stationRes.rows[0];

        // Check if operations key already exists
        const existingOpsKeyRes = await client.query<{
          status: string;
          source_id: string;
          fingerprint_sha256: string;
        }>(
          'SELECT status, source_id, fingerprint_sha256 FROM operations_source_keys WHERE key_id = $1',
          [key.keyId]
        );

        if (existingOpsKeyRes.rows.length > 0 && existingOpsKeyRes.rows[0]) {
          const row = existingOpsKeyRes.rows[0];
          if (row.source_id !== key.identityId) {
            throw new Error(
              `Cannot rebind key ${key.keyId} to different operations source: existing=${row.source_id}, attempted=${key.identityId}`
            );
          }
          if (row.fingerprint_sha256 !== computedFingerprint) {
            throw new Error(
              `Cannot overwrite operations key material for key ${key.keyId} with differing fingerprint`
            );
          }
          if (row.status === 'REVOKED') {
            continue;
          }
          registeredOpsSources++;
          continue;
        }

        await client.query(
          `INSERT INTO operations_source_keys (
             key_id, source_id, site_id, station_id, algorithm, public_key_pem, fingerprint_sha256, status, valid_from
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', $8)`,
          [
            key.keyId,
            key.identityId,
            site.id,
            station.id,
            key.algorithm,
            key.publicKeyPem,
            computedFingerprint,
            key.createdAt || new Date().toISOString(),
          ]
        );
        registeredOpsSources++;
      }
    }

    await client.query('COMMIT');
    console.log(
      `[REGISTRY] Registered ${registeredDevices} device key(s) and ${registeredOpsSources} ops source key(s) successfully.`
    );
    return { registeredDevices, registeredOpsSources };
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[REGISTRY] Failed to register keys:', (err as Error).message);
    throw err;
  } finally {
    client.release();
  }
}
