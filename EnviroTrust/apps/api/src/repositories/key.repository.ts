import type { Pool, PoolClient } from 'pg';

export interface RegisteredDeviceKey {
  id: string;
  keyId: string;
  sensorId: string; // UUID
  sensorCode: string;
  siteId: string; // UUID
  siteCode: string;
  stationId: string; // UUID
  stationCode: string;
  parameter: 'pH' | 'COD' | 'TSS';
  algorithm: 'Ed25519';
  publicKeyPem: string;
  fingerprintSha256: string;
  status: 'PENDING' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  validFrom: Date;
  validTo: Date | null;
  revokedAt: Date | null;
}

export interface RegisteredOperationsKey {
  id: string;
  keyId: string;
  sourceId: string;
  siteId: string; // UUID
  siteCode: string;
  stationId: string; // UUID
  stationCode: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  fingerprintSha256: string;
  status: 'PENDING' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  validFrom: Date;
  validTo: Date | null;
  revokedAt: Date | null;
}

export class KeyRepository {
  constructor(private readonly pool: Pool) {}

  async getDeviceKey(keyId: string, client?: PoolClient): Promise<RegisteredDeviceKey | null> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      key_id: string;
      sensor_id: string;
      sensor_code: string;
      site_id: string;
      site_code: string;
      station_id: string;
      station_code: string;
      parameter: 'pH' | 'COD' | 'TSS';
      algorithm: 'Ed25519';
      public_key_pem: string;
      fingerprint_sha256: string;
      status: 'PENDING' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
      valid_from: Date;
      valid_to: Date | null;
      revoked_at: Date | null;
    }>(
      `SELECT
         dk.id,
         dk.key_id,
         dk.sensor_id,
         s.sensor_code,
         st.site_id,
         si.site_code,
         s.station_id,
         st.station_code,
         s.parameter,
         dk.algorithm,
         dk.public_key_pem,
         dk.fingerprint_sha256,
         dk.status,
         dk.valid_from,
         dk.valid_to,
         dk.revoked_at
       FROM device_keys dk
       JOIN sensors s ON s.id = dk.sensor_id
       JOIN monitoring_stations st ON st.id = s.station_id
       JOIN sites si ON si.id = st.site_id
       WHERE dk.key_id = $1`,
      [keyId]
    );

    if (res.rows.length === 0 || !res.rows[0]) {
      return null;
    }

    const row = res.rows[0];
    return {
      id: row.id,
      keyId: row.key_id,
      sensorId: row.sensor_id,
      sensorCode: row.sensor_code,
      siteId: row.site_id,
      siteCode: row.site_code,
      stationId: row.station_id,
      stationCode: row.station_code,
      parameter: row.parameter,
      algorithm: row.algorithm,
      publicKeyPem: row.public_key_pem,
      fingerprintSha256: row.fingerprint_sha256,
      status: row.status,
      validFrom: row.valid_from,
      validTo: row.valid_to,
      revokedAt: row.revoked_at,
    };
  }

  async getOperationsKey(keyId: string, client?: PoolClient): Promise<RegisteredOperationsKey | null> {
    const q = client || this.pool;
    const res = await q.query<{
      id: string;
      key_id: string;
      source_id: string;
      site_id: string;
      site_code: string;
      station_id: string;
      station_code: string;
      algorithm: 'Ed25519';
      public_key_pem: string;
      fingerprint_sha256: string;
      status: 'PENDING' | 'ACTIVE' | 'REVOKED' | 'EXPIRED';
      valid_from: Date;
      valid_to: Date | null;
      revoked_at: Date | null;
    }>(
      `SELECT
         osk.id,
         osk.key_id,
         osk.source_id,
         osk.site_id,
         si.site_code,
         osk.station_id,
         st.station_code,
         osk.algorithm,
         osk.public_key_pem,
         osk.fingerprint_sha256,
         osk.status,
         osk.valid_from,
         osk.valid_to,
         osk.revoked_at
       FROM operations_source_keys osk
       JOIN sites si ON si.id = osk.site_id
       JOIN monitoring_stations st ON st.id = osk.station_id
       WHERE osk.key_id = $1`,
      [keyId]
    );

    if (res.rows.length === 0 || !res.rows[0]) {
      return null;
    }

    const row = res.rows[0];
    return {
      id: row.id,
      keyId: row.key_id,
      sourceId: row.source_id,
      siteId: row.site_id,
      siteCode: row.site_code,
      stationId: row.station_id,
      stationCode: row.station_code,
      algorithm: row.algorithm,
      publicKeyPem: row.public_key_pem,
      fingerprintSha256: row.fingerprint_sha256,
      status: row.status,
      validFrom: row.valid_from,
      validTo: row.valid_to,
      revokedAt: row.revoked_at,
    };
  }
}
