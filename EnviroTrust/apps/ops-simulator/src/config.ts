import path from 'node:path';
import type { OperatingMode } from '@envirotrust/contracts';

export const DEMO_SITE_ID = 'PLANT-001';
export const DEMO_STATION_ID = 'ETP-OUTLET-001';
export const OPS_SOURCE_ID = 'OPS-001';

export interface OpsScenarioParams {
  mode: OperatingMode;
  productionRateRange: [number, number];
  wastewaterFlowRange: [number, number];
  treatmentDoseRange: [number, number];
  energyConsumptionRange: [number, number];
}

export const OPS_SCENARIOS: Record<OperatingMode, OpsScenarioParams> = {
  NORMAL: {
    mode: 'NORMAL',
    productionRateRange: [400, 500],
    wastewaterFlowRange: [10000, 14000],
    treatmentDoseRange: [30, 40],
    energyConsumptionRange: [480, 550],
  },
  HIGH_LOAD: {
    mode: 'HIGH_LOAD',
    productionRateRange: [750, 950],
    wastewaterFlowRange: [18000, 24000],
    treatmentDoseRange: [55, 75],
    energyConsumptionRange: [800, 980],
  },
  CLEANING: {
    mode: 'CLEANING',
    productionRateRange: [50, 150],
    wastewaterFlowRange: [15000, 20000],
    treatmentDoseRange: [70, 90],
    energyConsumptionRange: [300, 400],
  },
  LOW_LOAD: {
    mode: 'LOW_LOAD',
    productionRateRange: [150, 250],
    wastewaterFlowRange: [4000, 7000],
    treatmentDoseRange: [15, 25],
    energyConsumptionRange: [200, 300],
  },
};

export function getDefaultOpsKeyDir(rootDir: string): string {
  return path.resolve(rootDir, 'local-secrets', 'ops-keys', OPS_SOURCE_ID);
}

