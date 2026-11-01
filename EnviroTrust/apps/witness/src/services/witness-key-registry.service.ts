import fs from 'node:fs';
import path from 'node:path';
import type { Pool } from 'pg';
import { computePublicKeyFingerprint } from '@envirotrust/crypto';
import { getWitnessDbPool } from '../db/connection.js';

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

export async function registerWitnessKeys(
  manifestPath?: string,
  customPool?: Pool
): Promise<{
  registeredSensorKeys: number;
  registeredOpsKeys: number;
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

  const pool = customPool || getWitnessDbPool();
  const client = await pool.connect();
  let registeredSensorKeys = 0;
  let registeredOpsKeys = 0;

  try {
    await client.query('BEGIN');

    for (const key of manifest.keys) {
      if (key.algorithm !== 'Ed25519') {
        throw new Error(`Unsupported algorithm ${key.algorithm} for key ${key.keyId}`);
      }

      const computedFingerprint = computePublicKeyFingerprint(key.publicKeyPem);
      if (computedFingerprint !== key.publicKeyFingerprint) {
        throw new Error(
          `Witness key registration fingerprint mismatch for ${key.keyId}! Manifest: ${key.publicKeyFingerprint}, Computed: ${computedFingerprint}`
        );
      }

      if (key.identityType === 'SENSOR') {
        const existingRes = await client.query<{
          sensor_code: string;
          fingerprint_sha256: string;
          status: string;
        }>('SELECT sensor_code, fingerprint_sha256, status FROM witness_sensor_keys WHERE key_id = $1', [
          key.keyId,
        ]);

        if (existingRes.rows.length > 0 && existingRes.rows[0]) {
          const existing = existingRes.rows[0];
          if (existing.sensor_code !== key.identityId) {
            throw new Error(
              `Witness key collision: key ${key.keyId} already bound to ${existing.sensor_code}, cannot bind to ${key.identityId}`
            );
          }
          if (existing.fingerprint_sha256 !== computedFingerprint) {
            throw new Error(`Cannot overwrite key material for witness key ${key.keyId}`);
          }
          if (existing.status === 'REVOKED') {
            // Never reactivate revoked keys
            continue;
          }
          registeredSensorKeys++;
          continue;
        }

        await client.query(
          `INSERT INTO witness_sensor_keys (
             key_id, sensor_code, site_code, station_code, parameter, public_key_pem, fingerprint_sha256, status, provisioned_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', now())`,
          [
            key.keyId,
            key.identityId,
            key.siteId,
            key.stationId,
            key.parameter || 'UNKNOWN',
            key.publicKeyPem,
            computedFingerprint,
          ]
        );
        registeredSensorKeys++;
      } else if (key.identityType === 'OPERATIONS_SOURCE') {
        const existingRes = await client.query<{
          source_id: string;
          fingerprint_sha256: string;
          status: string;
        }>('SELECT source_id, fingerprint_sha256, status FROM witness_operations_keys WHERE key_id = $1', [
          key.keyId,
        ]);

        if (existingRes.rows.length > 0 && existingRes.rows[0]) {
          const existing = existingRes.rows[0];
          if (existing.source_id !== key.identityId) {
            throw new Error(
              `Witness operations key collision: key ${key.keyId} already bound to ${existing.source_id}, cannot bind to ${key.identityId}`
            );
          }
          if (existing.fingerprint_sha256 !== computedFingerprint) {
            throw new Error(`Cannot overwrite operations key material for witness key ${key.keyId}`);
          }
          if (existing.status === 'REVOKED') {
            continue;
          }
          registeredOpsKeys++;
          continue;
        }

        await client.query(
          `INSERT INTO witness_operations_keys (
             key_id, source_id, site_code, station_code, algorithm, public_key_pem, fingerprint_sha256, status, provisioned_at
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', now())`,
          [
            key.keyId,
            key.identityId,
            key.siteId,
            key.stationId,
            key.algorithm,
            key.publicKeyPem,
            computedFingerprint,
          ]
        );
        registeredOpsKeys++;
      }
    }

    await client.query('COMMIT');
    console.log(
      `[WITNESS_REGISTRY] Registered ${registeredSensorKeys} sensor key(s) and ${registeredOpsKeys} operations key(s) successfully.`
    );
    return { registeredSensorKeys, registeredOpsKeys };
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[WITNESS_REGISTRY] Failed to register keys:', (err as Error).message);
    throw err;
  } finally {
    client.release();
  }
}

