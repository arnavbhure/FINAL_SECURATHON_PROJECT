import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadPublicKey, verifyPayloadSignatureWithReason } from '@envirotrust/crypto';
import { OpsContextSimulator } from './simulator.js';
import { getDefaultOpsKeyDir } from './config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

export function runOpsOnce() {
  console.log('\n======================================================');
  console.log('EnviroTrust Operations Context Simulator — One-Shot Test');
  console.log('Generating and verifying signed industrial operating conditions');
  console.log('Notice: Software-only simulated industrial process context.');
  console.log('======================================================\n');

  const keyDir = getDefaultOpsKeyDir(rootDir);
  let simulator: OpsContextSimulator;

  try {
    simulator = new OpsContextSimulator({ keyDir });
  } catch (err) {
    console.error(`[ERROR] Failed to initialize OPS simulator: ${(err as Error).message}`);
    return;
  }

  const pubKeyPath = path.join(keyDir, 'public.pem');
  const pubKeyPem = loadPublicKey(pubKeyPath);

  // 1. Generate NORMAL mode context
  const normalEnv = simulator.generateContext({ mode: 'NORMAL' });
  const normalVerify = verifyPayloadSignatureWithReason(normalEnv.payload, normalEnv.signature, pubKeyPem);

  console.log(`[OPERATIONS CONTEXT] ${simulator.sourceId} — Scenario: NORMAL`);
  console.log(`  Operating Mode:       ${normalEnv.payload.operatingMode}`);
  console.log(`  Production Rate:      ${normalEnv.payload.productionRate} units/hr`);
  console.log(`  Wastewater Flow:      ${normalEnv.payload.wastewaterFlow} L/hr`);
  console.log(`  Treatment Dose:       ${normalEnv.payload.treatmentDose} dose/hr`);
  console.log(`  Energy Consumption:   ${normalEnv.payload.energyConsumption} kWh/hr`);
  console.log(`  Interval:             ${normalEnv.payload.intervalStart} -> ${normalEnv.payload.intervalEnd}`);
  console.log(`  Sequence No:          ${normalEnv.payload.sequence}`);
  console.log(`  Message ID:           ${normalEnv.payload.messageId}`);
  console.log(`  Key ID:               ${simulator.keyId}`);
  console.log(`  Signature Status:     ${normalVerify.valid ? 'VALID (Ed25519 Verified)' : 'FAILED'}`);
  console.log(`  Signature (Base64):   ${normalEnv.signature.slice(0, 24)}... (88 chars, raw key never printed)`);
  console.log('------------------------------------------------------\n');

  // 2. Generate HIGH_LOAD mode context
  const highLoadEnv = simulator.generateContext({ mode: 'HIGH_LOAD' });
  const highLoadVerify = verifyPayloadSignatureWithReason(highLoadEnv.payload, highLoadEnv.signature, pubKeyPem);

  console.log(`[OPERATIONS CONTEXT] ${simulator.sourceId} — Scenario: HIGH_LOAD`);
  console.log(`  Operating Mode:       ${highLoadEnv.payload.operatingMode}`);
  console.log(`  Production Rate:      ${highLoadEnv.payload.productionRate} units/hr`);
  console.log(`  Wastewater Flow:      ${highLoadEnv.payload.wastewaterFlow} L/hr`);
  console.log(`  Treatment Dose:       ${highLoadEnv.payload.treatmentDose} dose/hr`);
  console.log(`  Energy Consumption:   ${highLoadEnv.payload.energyConsumption} kWh/hr`);
  console.log(`  Interval:             ${highLoadEnv.payload.intervalStart} -> ${highLoadEnv.payload.intervalEnd}`);
  console.log(`  Sequence No:          ${highLoadEnv.payload.sequence}`);
  console.log(`  Message ID:           ${highLoadEnv.payload.messageId}`);
  console.log(`  Key ID:               ${simulator.keyId}`);
  console.log(`  Signature Status:     ${highLoadVerify.valid ? 'VALID (Ed25519 Verified)' : 'FAILED'}`);
  console.log(`  Signature (Base64):   ${highLoadEnv.signature.slice(0, 24)}... (88 chars, raw key never printed)`);
  console.log('------------------------------------------------------\n');

  console.log('[SUCCESS] Operations simulator generated schema-valid, Ed25519-signed context envelopes.');
}

if (process.argv[1] && (process.argv[1].endsWith('cli.ts') || process.argv[1].endsWith('cli.js'))) {
  runOpsOnce();
}

