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

export async function sendAllSensorsOnce() {
  const isDual = process.argv.includes('--dual') || process.env['DUAL_DELIVERY'] === 'true';
  const primaryUrl =
    process.env['PRIMARY_INGESTION_URL'] || 'http://localhost:4000/api/v1/ingestion/readings';
  const witnessUrl =
    process.env['WITNESS_INGESTION_URL'] || 'http://localhost:4001/witness/v1/ingestion/readings';

  console.log('\n======================================================');
  console.log(`EnviroTrust Sensor Simulator — HTTP Dispatch (${isDual ? 'Dual-Delivery' : 'Send-Once'})`);
  console.log(`Primary Target: ${primaryUrl}`);
  if (isDual) {
    console.log(`Witness Target: ${witnessUrl}`);
  }
  console.log('Notice: Software-only simulated industrial effluent telemetry.');
  console.log('======================================================\n');

  const sensorIds = Object.keys(SENSOR_PROFILES) as Array<'PH-OUT-001' | 'COD-OUT-001' | 'TSS-OUT-001'>;
  let successCount = 0;

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

    let device: SensorDevice;
    try {
      device = new SensorDevice({
        sensorId,
        keyDir,
        initialTelemetrySequence: currentSequence,
        bootId,
      });
    } catch (err) {
      console.error(`[ERROR] Failed to load sensor identity ${sensorId}: ${(err as Error).message}`);
      continue;
    }

    try {
      if (isDual) {
        const dualResult = await device.sendReadingDual(primaryUrl, witnessUrl);
        console.log(`[DUAL DISPATCH] ${sensorId}`);
        console.log(`  Message ID:       ${dualResult.envelope.payload.messageId}`);
        console.log(`  Sequence:         ${dualResult.envelope.payload.sequence}`);
        console.log(`  Parameter:        ${dualResult.envelope.payload.parameter} = ${dualResult.envelope.payload.value} ${dualResult.envelope.payload.unit}`);
        console.log(`  Primary Outcome:  ${dualResult.primary.status} (HTTP ${dualResult.primary.httpStatus ?? 'ERR'})`);
        console.log(`  Witness Outcome:  ${dualResult.witness.status} (HTTP ${dualResult.witness.httpStatus ?? 'ERR'})`);
        console.log('------------------------------------------------------');

        if (dualResult.primary.status === 'PRIMARY_ACCEPTED' || dualResult.witness.status === 'WITNESS_ACCEPTED') {
          successCount++;
          fs.writeFileSync(
            stateFile,
            JSON.stringify(
              {
                lastSequence: dualResult.envelope.payload.sequence,
                bootId: dualResult.envelope.payload.bootId,
              },
              null,
              2
            ),
            'utf-8'
          );
        }
      } else {
        const result = await device.sendReading(primaryUrl);
        console.log(`[DISPATCH] ${sensorId}`);
        console.log(`  HTTP Status:      ${result.status} ${result.ok ? '(OK)' : '(FAILED)'}`);
        console.log(`  Message ID:       ${result.envelope.payload.messageId}`);
        console.log(`  Sequence:         ${result.envelope.payload.sequence}`);
        console.log(`  Boot ID:          ${result.envelope.payload.bootId}`);
        console.log(`  Parameter:        ${result.envelope.payload.parameter} = ${result.envelope.payload.value} ${result.envelope.payload.unit}`);
        console.log(`  Response:        `, JSON.stringify(result.data));
        console.log('------------------------------------------------------');

        if (result.ok) {
          successCount++;
          fs.writeFileSync(
            stateFile,
            JSON.stringify(
              {
                lastSequence: result.envelope.payload.sequence,
                bootId: result.envelope.payload.bootId,
              },
              null,
              2
            ),
            'utf-8'
          );
        }
      }
    } catch (err) {
      console.error(`[DISPATCH FAILED] ${sensorId}: ${(err as Error).message}`);
    }
  }

  console.log(`\nDispatched readings for ${successCount}/${sensorIds.length} sensors successfully.`);
}

sendAllSensorsOnce().catch((err) => {
  console.error('[FATAL] Sensor dispatch failed:', (err as Error).message);
  process.exit(1);
});
