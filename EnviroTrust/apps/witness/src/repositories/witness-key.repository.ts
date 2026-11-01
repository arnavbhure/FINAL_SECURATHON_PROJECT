import type { Pool, PoolClient } from 'pg';

export interface RegisteredWitnessSensorKey {
  keyId: string;
  sensorCode: string;
  siteCode: string;
  stationCode: string;
  parameter: string;
  publicKeyPem: string;
  fingerprintSha256: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  provisionedAt: Date;
}

export interface RegisteredWitnessOperationsKey {
  keyId: string;
  sourceId: string;
  siteCode: string;
  stationCode: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  fingerprintSha256: string;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  provisionedAt: Date;
}

export class WitnessKeyRepository {
  constructor(private readonly pool: Pool) {}

  async getSensorKey(keyId: string, client?: PoolClient): Promise<RegisteredWitnessSensorKey | null> {
    const q = client || this.pool;
    const res = await q.query<{
      key_id: string;
      sensor_code: string;
      site_code: string;
      station_code: string;
      parameter: string;
      public_key_pem: string;
      fingerprint_sha256: string;
      status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
      provisioned_at: Date;
    }>(
      `SELECT key_id, sensor_code, site_code, station_code, parameter, public_key_pem, fingerprint_sha256, status, provisioned_at
       FROM witness_sensor_keys
       WHERE key_id = $1`,
      [keyId]
    );

    if (res.rows.length === 0 || !res.rows[0]) {
      return null;
    }

    const row = res.rows[0];
    return {
      keyId: row.key_id,
      sensorCode: row.sensor_code,
      siteCode: row.site_code,
      stationCode: row.station_code,
      parameter: row.parameter,
      publicKeyPem: row.public_key_pem,
      fingerprintSha256: row.fingerprint_sha256,
      status: row.status,
      provisionedAt: row.provisioned_at,
    };
  }

  async getOperationsKey(keyId: string, client?: PoolClient): Promise<RegisteredWitnessOperationsKey | null> {
    const q = client || this.pool;
    const res = await q.query<{
      key_id: string;
      source_id: string;
      site_code: string;
      station_code: string;
      algorithm: 'Ed25519';
      public_key_pem: string;
      fingerprint_sha256: string;
      status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
      provisioned_at: Date;
    }>(
      `SELECT key_id, source_id, site_code, station_code, algorithm, public_key_pem, fingerprint_sha256, status, provisioned_at
       FROM witness_operations_keys
       WHERE key_id = $1`,
      [keyId]
    );

    if (res.rows.length === 0 || !res.rows[0]) {
      return null;
    }

    const row = res.rows[0];
    return {
      keyId: row.key_id,
      sourceId: row.source_id,
      siteCode: row.site_code,
      stationCode: row.station_code,
      algorithm: row.algorithm,
      publicKeyPem: row.public_key_pem,
      fingerprintSha256: row.fingerprint_sha256,
      status: row.status,
      provisionedAt: row.provisioned_at,
    };
  }
}

