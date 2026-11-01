import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { SensorDevice } from './sensor.js';
import { SENSOR_PROFILES, getDefaultKeyDir } from './config.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../..');

const intervalMs = Number(process.env['SENSOR_TELEMETRY_INTERVAL_MS'] || 5000);
const isDual = process.env['DUAL_DELIVERY'] !== 'false';
const primaryTelemetryUrl =
  process.env['PRIMARY_INGESTION_URL'] || 'http://localhost:4000/api/v1/ingestion/readings';
const witnessTelemetryUrl =
  process.env['WITNESS_INGESTION_URL'] || 'http://localhost:4001/witness/v1/ingestion/readings';
const primaryHeartbeatUrl =
  process.env['PRIMARY_HEARTBEAT_URL'] || 'http://localhost:4000/api/v1/ingestion/heartbeats';
const witnessHeartbeatUrl =
  process.env['WITNESS_HEARTBEAT_URL'] || 'http://localhost:4001/witness/v1/ingestion/heartbeats';
const witnessToken =
  process.env['WITNESS_INGESTION_TOKEN'] || 'witness_ingestion_internal_token_secret_98765';

let isRunning = true;

process.on('SIGINT', () => {
  console.log('\n[SIMULATED SENSOR STREAM] Stopping stream cleanly (SIGINT received)...');
  isRunning = false;
});
process.on('SIGTERM', () => {
  console.log('\n[SIMULATED SENSOR STREAM] Stopping stream cleanly (SIGTERM received)...');
  isRunning = false;
});

export async function runSensorStream() {
  console.log('======================================================');
  console.log('EnviroTrust Continuous Sensor Telemetry & Heartbeat Stream');
  console.log(`Interval:        ${intervalMs}ms`);
  console.log(`Dual-Delivery:   ${isDual ? 'ENABLED (Primary + Witness)' : 'DISABLED (Primary Only)'}`);
  console.log(`Primary Target:  ${primaryTelemetryUrl}`);
  if (isDual) {
    console.log(`Witness Target:  ${witnessTelemetryUrl}`);
  }
  console.log('Notice: Software-simulated industrial effluent telemetry.');
  console.log('Press Ctrl+C to stop cleanly.');
  console.log('======================================================\n');

  const sensorIds = Object.keys(SENSOR_PROFILES) as Array<'PH-OUT-001' | 'COD-OUT-001' | 'TSS-OUT-001'>;
  const devices: Record<string, { device: SensorDevice; stateFile: string }> = {};

  for (const sensorId of sensorIds) {
    const keyDir = getDefaultKeyDir(rootDir, sensorId);
    const stateFile = path.join(keyDir, 'sequence-state.json');

    let currentSequence = 1;
    let bootId: string | undefined;

    if (fs.existsSync(stateFile)) {
      try {
        const state = JSON.parse(fs.readFileSync(stateFile, 'utf-8')) as {
          lastSequence?: number;
          bootId?: string;
        };
        currentSequence = (state.lastSequence || 0) + 1;
        bootId = state.bootId;
      } catch {
        currentSequence = 1;
      }
    }

    try {
      const device = new SensorDevice({
        sensorId,
        keyDir,
        initialTelemetrySequence: currentSequence,
        bootId,
      });
      devices[sensorId] = { device, stateFile };
    } catch (err: any) {
      console.error(`[ERROR] Failed to initialize sensor ${sensorId}: ${err.message}`);
    }
  }

  let tick = 0;
  while (isRunning) {
    tick++;
    const timestamp = new Date().toISOString();
    console.log(`\n--- [STREAM TICK #${tick}] ${timestamp} ---`);

    for (const sensorId of sensorIds) {
      const entry = devices[sensorId];
      if (!entry) continue;

      const { device, stateFile } = entry;

      try {
        // 1. Send telemetry reading
        if (isDual) {
          const dualResult = await device.sendReadingDual(primaryTelemetryUrl, witnessTelemetryUrl, {
            witnessToken,
          });
          const val = dualResult.envelope.payload.value;
          const unit = dualResult.envelope.payload.unit;
          const param = dualResult.envelope.payload.parameter;
          const seq = dualResult.envelope.payload.sequence;
          const pStatus = dualResult.primary.status;
          const wStatus = dualResult.witness.status;

          console.log(`[READING] ${sensorId} (${param}): ${val} ${unit} | Seq #${seq} | Primary: ${pStatus} | Witness: ${wStatus}`);

          // Persist state on acceptance
          if (dualResult.primary.status === 'PRIMARY_ACCEPTED' || dualResult.witness.status === 'WITNESS_ACCEPTED') {
            fs.writeFileSync(
              stateFile,
              JSON.stringify(
                {
                  lastSequence: dualResult.envelope.payload.sequence,
                  bootId: dualResult.envelope.payload.bootId,
                  updatedAt: new Date().toISOString(),
                },
                null,
                2
              ),
              'utf-8'
            );
          }
        } else {
          const result = await device.sendReading(primaryTelemetryUrl);
          console.log(`[READING] ${sensorId}: ${result.envelope.payload.value} ${result.envelope.payload.unit} (Seq #${result.envelope.payload.sequence})`);
        }

        // 2. Send heartbeat to keep sensor ONLINE
        if (isDual) {
          await device.sendHeartbeatDual(primaryHeartbeatUrl, witnessHeartbeatUrl, { witnessToken });
        } else {
          await device.sendHeartbeat(primaryHeartbeatUrl);
        }
      } catch (err: any) {
        console.error(`[STREAM ERROR] ${sensorId}: ${err.message}`);
      }
    }

    if (!isRunning) break;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  console.log('[SIMULATED SENSOR STREAM] Shutdown complete.');
}

// Execute directly if run as main CLI script
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runSensorStream().catch((err) => {
    console.error('[FATAL STREAM ERROR]:', err);
    process.exit(1);
  });
}

