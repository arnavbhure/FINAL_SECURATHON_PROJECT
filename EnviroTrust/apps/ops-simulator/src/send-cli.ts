import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { OpsContextSimulator } from './simulator.js';
import { getDefaultOpsKeyDir } from './config.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

export async function sendOpsOnce() {
  const isDual = process.argv.includes('--dual') || process.env['DUAL_DELIVERY'] === 'true';
  const primaryUrl =
    process.env['PRIMARY_OPS_INGESTION_URL'] ||
    'http://localhost:4000/api/v1/ingestion/operations-context';
  const witnessUrl =
    process.env['WITNESS_OPS_INGESTION_URL'] ||
    'http://localhost:4001/witness/v1/ingestion/operations-context';

  console.log('\n======================================================');
  console.log(`EnviroTrust Operations Simulator — HTTP Dispatch (${isDual ? 'Dual-Delivery' : 'Send-Once'})`);
  console.log(`Primary Target: ${primaryUrl}`);
  if (isDual) {
    console.log(`Witness Target: ${witnessUrl}`);
  }
  console.log('Notice: Software-only simulated industrial operations context.');
  console.log('======================================================\n');

  const keyDir = getDefaultOpsKeyDir(rootDir);
  const stateFile = path.join(keyDir, 'sequence-state.json');

  let currentSequence = 1;
  if (fs.existsSync(stateFile)) {
    try {
      const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8')) as { lastSequence?: number };
      currentSequence = (state.lastSequence || 0) + 1;
    } catch {
      currentSequence = 1;
    }
  }

  let simulator: OpsContextSimulator;
  try {
    simulator = new OpsContextSimulator({ keyDir, initialSequence: currentSequence });
  } catch (err) {
    console.error(`[ERROR] Failed to load operations identity: ${(err as Error).message}`);
    process.exit(1);
  }

  try {
    if (isDual) {
      const dualResult = await simulator.sendOpsContextDual(primaryUrl, witnessUrl);
      console.log(`[DUAL DISPATCH] ${simulator.sourceId}`);
      console.log(`  Message ID:       ${dualResult.envelope.payload.messageId}`);
      console.log(`  Sequence:         ${dualResult.envelope.payload.sequence}`);
      console.log(`  Operating Mode:   ${dualResult.envelope.payload.operatingMode}`);
      console.log(`  Production Rate:  ${dualResult.envelope.payload.productionRate} units/hr`);
      console.log(`  Primary Outcome:  ${dualResult.primary.status} (HTTP ${dualResult.primary.httpStatus ?? 'ERR'})`);
      console.log(`  Witness Outcome:  ${dualResult.witness.status} (HTTP ${dualResult.witness.httpStatus ?? 'ERR'})`);
      console.log('------------------------------------------------------');

      if (dualResult.primary.status === 'PRIMARY_ACCEPTED' || dualResult.witness.status === 'WITNESS_ACCEPTED') {
        fs.writeFileSync(
          stateFile,
          JSON.stringify({ lastSequence: dualResult.envelope.payload.sequence }, null, 2),
          'utf-8'
        );
      } else {
        process.exit(1);
      }
    } else {
      const result = await simulator.sendOpsContext(primaryUrl);
      console.log(`[DISPATCH] ${simulator.sourceId}`);
      console.log(`  HTTP Status:      ${result.status} ${result.ok ? '(OK)' : '(FAILED)'}`);
      console.log(`  Message ID:       ${result.envelope.payload.messageId}`);
      console.log(`  Sequence:         ${result.envelope.payload.sequence}`);
      console.log(`  Operating Mode:   ${result.envelope.payload.operatingMode}`);
      console.log(`  Production Rate:  ${result.envelope.payload.productionRate} units/hr`);
      console.log(`  Wastewater Flow:  ${result.envelope.payload.wastewaterFlow} m3/hr`);
      console.log(`  Treatment Dose:   ${result.envelope.payload.treatmentDose} mg/L`);
      console.log(`  Energy Consump:   ${result.envelope.payload.energyConsumption} kWh`);
      console.log(`  Response:        `, JSON.stringify(result.data));
      console.log('------------------------------------------------------');

      if (result.ok) {
        fs.writeFileSync(
          stateFile,
          JSON.stringify({ lastSequence: result.envelope.payload.sequence }, null, 2),
          'utf-8'
        );
      } else {
        process.exit(1);
      }
    }
  } catch (err) {
    console.error(`[DISPATCH FAILED]: ${(err as Error).message}`);
    process.exit(1);
  }
}

sendOpsOnce().catch((err) => {
  console.error('[FATAL] Operations dispatch failed:', (err as Error).message);
  process.exit(1);
});
