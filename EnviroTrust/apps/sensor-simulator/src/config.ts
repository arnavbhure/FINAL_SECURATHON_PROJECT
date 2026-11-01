import path from 'node:path';

export interface SensorProfile {
  sensorId: string;
  parameter: 'pH' | 'COD' | 'TSS';
  unit: string;
  nominalMin: number;
  nominalMax: number;
  decimals: number;
  baseKeyPrefix: string;
}

export const DEMO_SITE_ID = 'PLANT-001';
export const DEMO_STATION_ID = 'ETP-OUTLET-001';

export const SENSOR_PROFILES: Record<string, SensorProfile> = {
  'PH-OUT-001': {
    sensorId: 'PH-OUT-001',
    parameter: 'pH',
    unit: 'pH',
    nominalMin: 6.8,
    nominalMax: 7.8,
    decimals: 2,
    baseKeyPrefix: 'PH-KEY',
  },
  'COD-OUT-001': {
    sensorId: 'COD-OUT-001',
    parameter: 'COD',
    unit: 'mg/L',
    nominalMin: 170.0,
    nominalMax: 230.0,
    decimals: 2,
    baseKeyPrefix: 'COD-KEY',
  },
  'TSS-OUT-001': {
    sensorId: 'TSS-OUT-001',
    parameter: 'TSS',
    unit: 'mg/L',
    nominalMin: 35.0,
    nominalMax: 65.0,
    decimals: 2,
    baseKeyPrefix: 'TSS-KEY',
  },
};

export function getDefaultKeyDir(rootDir: string, sensorId: string): string {
  return path.resolve(rootDir, 'local-secrets', 'sensor-keys', sensorId);
}

