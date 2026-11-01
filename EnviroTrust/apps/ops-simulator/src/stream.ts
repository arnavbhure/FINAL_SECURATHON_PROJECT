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

const intervalMs = Number(process.env['OPS_CONTEXT_INTERVAL_MS'] || 15000);
const isDual = process.env['DUAL_DELIVERY'] !== 'false';
const primaryUrl =
  process.env['PRIMARY_OPS_INGESTION_URL'] ||
  'http://localhost:4000/api/v1/ingestion/operations-context';
const witnessUrl =
  process.env['WITNESS_OPS_INGESTION_URL'] ||
  'http://localhost:4001/witness/v1/ingestion/operations-context';
const witnessToken =
  process.env['WITNESS_INGESTION_TOKEN'] ||
  'witness_ingestion_internal_token_secret_98765';

let isRunning = true;

process.on('SIGINT', () => {
  console.log('\n[SIMULATED OPS STREAM] Stopping stream cleanly (SIGINT received)...');
  isRunning = false;
});
process.on('SIGTERM', () => {
  console.log('\n[SIMULATED OPS STREAM] Stopping stream cleanly (SIGTERM received)...');
  isRunning = false;
});

export async function runOpsStream() {
  console.log('======================================================');
  console.log('EnviroTrust Continuous Operations Context Stream (OPS-001)');
  console.log(`Interval:        ${intervalMs}ms`);
  console.log(`Dual-Delivery:   ${isDual ? 'ENABLED (Primary + Witness)' : 'DISABLED (Primary Only)'}`);
  console.log(`Primary Target:  ${primaryUrl}`);
  if (isDual) {
    console.log(`Witness Target:  ${witnessUrl}`);
  }
  console.log('Notice: Software-simulated industrial operating context.');
  console.log('Press Ctrl+C to stop cleanly.');
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
  } catch (err: any) {
    console.error(`[ERROR] Failed to load operations identity: ${err.message}`);
    process.exit(1);
  }

  let tick = 0;
  while (isRunning) {
    tick++;
    const timestamp = new Date().toISOString();
    console.log(`\n--- [OPS TICK #${tick}] ${timestamp} ---`);

    try {
      if (isDual) {
        const dualResult = await simulator.sendOpsContextDual(primaryUrl, witnessUrl, { witnessToken });
        const p = dualResult.envelope.payload;
        console.log(`[OPS CONTEXT] Seq #${p.sequence} | Mode: ${p.operatingMode} | Prod: ${p.productionRate} u/h | Flow: ${p.wastewaterFlow} m3/h | Primary: ${dualResult.primary.status} | Witness: ${dualResult.witness.status}`);

        if (dualResult.primary.status === 'PRIMARY_ACCEPTED' || dualResult.witness.status === 'WITNESS_ACCEPTED') {
          fs.writeFileSync(
            stateFile,
            JSON.stringify(
              {
                lastSequence: p.sequence,
                updatedAt: new Date().toISOString(),
              },
              null,
              2
            ),
            'utf-8'
          );
        }
      } else {
        const result = await simulator.sendOpsContext(primaryUrl);
        console.log(`[OPS CONTEXT] Seq #${result.envelope.payload.sequence} | Mode: ${result.envelope.payload.operatingMode}`);
      }
    } catch (err: any) {
      console.error(`[OPS STREAM ERROR]: ${err.message}`);
    }

    if (!isRunning) break;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  console.log('[SIMULATED OPS STREAM] Shutdown complete.');
}

// Execute directly if run as main CLI script
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runOpsStream().catch((err) => {
    console.error('[FATAL OPS STREAM ERROR]:', err);
    process.exit(1);
  });
}

