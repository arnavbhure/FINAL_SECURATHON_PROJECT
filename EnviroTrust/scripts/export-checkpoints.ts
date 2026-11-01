import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';
import { getWitnessDbPool, closeWitnessDbPool } from '../apps/witness/src/db/connection.js';
import { WitnessEventRepository, type WitnessEventDataWithoutHash } from '../apps/witness/src/repositories/witness-event.repository.js';
import { CheckpointService } from '../apps/witness/src/services/checkpoint.service.js';

dotenv.config();

export interface CheckpointExportFile {
  exportedAt: string;
  stationId: string;
  witnessPublicKeyFingerprint: string;
  witnessPublicKeyPem: string;
  checkpoints: Array<{
    id: string;
    payload: {
      schemaVersion: 1;
      checkpointId: string;
      witnessId: string;
      witnessKeyId: string;
      siteId: string;
      stationId: string;
      checkpointSequence: number;
      lastWitnessSequence: number;
      chainHeadHash: string;
      previousCheckpointHash: string;
      createdAt: string;
    };
    signature: string;
    checkpointHash: string;
    witnessPublicKeyFingerprint: string;
    events: Array<{
      witnessSequence: number;
      eventType: 'TELEMETRY' | 'OPERATIONS_CONTEXT';
      messageId: string;
      previousHash: string;
      eventHash: string;
      eventDataWithoutHash: WitnessEventDataWithoutHash;
    }>;
  }>;
}

function findWitnessKeyDir(): string {
  const envVal = process.env['WITNESS_KEY_DIR'];
  if (envVal) {
    const directPath = path.resolve(process.cwd(), envVal);
    if (fs.existsSync(path.join(directPath, 'public.pem'))) {
      return directPath;
    }
    const upPath = path.resolve(process.cwd(), '../../', envVal);
    if (fs.existsSync(path.join(upPath, 'public.pem'))) {
      return upPath;
    }
  }
  const candidates = [
    path.resolve(process.cwd(), 'local-secrets/witness-keys'),
    path.resolve(process.cwd(), '../../local-secrets/witness-keys'),
    path.resolve(process.cwd(), '../local-secrets/witness-keys'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'public.pem'))) return c;
  }
  return path.resolve(process.cwd(), 'local-secrets/witness-keys');
}

export async function exportCheckpoints(options: {
  stationId?: string;
  outputPath?: string;
  keyDir?: string;
} = {}): Promise<string> {
  const stationId = options.stationId || 'ETP-OUTLET-001';
  const outputPath = options.outputPath || path.resolve(process.cwd(), 'witness-checkpoint-export.json');
  const keyDir = options.keyDir || findWitnessKeyDir();

  const pool = getWitnessDbPool();
  const repo = new WitnessEventRepository(pool);
  const checkpointService = new CheckpointService(keyDir);

  const publicKeyPem = checkpointService.getPublicKeyPem();
  const fingerprint = checkpointService.getPublicKeyFingerprint();

  try {
    const dbCheckpoints = await repo.getCheckpointsForStation(stationId);
    if (dbCheckpoints.length === 0) {
      console.log(`[EXPORT] No checkpoints found in database for station ${stationId}.`);
    }

    const exportedCheckpoints: CheckpointExportFile['checkpoints'] = [];
    let previousLastSeq = 0;

    for (const cp of dbCheckpoints) {
      const fromSeq = previousLastSeq + 1;
      const toSeq = cp.lastWitnessSequence;
      const events = await repo.getEventsForStation(stationId, fromSeq, toSeq);

      const parsedPayload = JSON.parse(cp.canonicalPayload);

      exportedCheckpoints.push({
        id: cp.id,
        payload: parsedPayload,
        signature: cp.signatureBase64,
        checkpointHash: cp.checkpointHash,
        witnessPublicKeyFingerprint: cp.witnessPublicKeyFingerprint,
        events: events.map((ev) => {
          const eventDataWithoutHash: WitnessEventDataWithoutHash = {
            schemaVersion: 1,
            stationCode: ev.stationCode,
            siteCode: ev.siteCode,
            witnessSequence: ev.witnessSequence,
            eventType: ev.eventType,
            identityType: ev.identityType,
            identityCode: ev.identityCode,
            keyId: ev.keyId,
            bootId: ev.bootId,
            sourceSequence: ev.sourceSequence,
            sourceTimestamp: ev.sourceTimestamp.toISOString(),
            messageId: ev.messageId,
            payloadHash: ev.payloadHash,
            signatureHash: ev.signatureHash,
            witnessReceivedAt: ev.witnessReceivedAt.toISOString(),
            previousHash: ev.previousHash,
          };

          return {
            witnessSequence: ev.witnessSequence,
            eventType: ev.eventType,
            messageId: ev.messageId,
            previousHash: ev.previousHash,
            eventHash: ev.eventHash,
            eventDataWithoutHash,
          };
        }),
      });

      previousLastSeq = toSeq;
    }

    const exportFile: CheckpointExportFile = {
      exportedAt: new Date().toISOString(),
      stationId,
      witnessPublicKeyFingerprint: fingerprint,
      witnessPublicKeyPem: publicKeyPem,
      checkpoints: exportedCheckpoints,
    };

    fs.writeFileSync(outputPath, JSON.stringify(exportFile, null, 2), 'utf-8');
    console.log(`[EXPORT] Exported ${exportedCheckpoints.length} checkpoint(s) to ${outputPath}`);
    return outputPath;
  } finally {
    await closeWitnessDbPool();
  }
}

// CLI entry point
if (process.argv[1] && process.argv[1].endsWith('export-checkpoints.ts')) {
  const stationArg = process.argv.find((a) => a.startsWith('--station='));
  const outputArg = process.argv.find((a) => a.startsWith('--output='));

  const stationId = stationArg ? stationArg.split('=')[1] : undefined;
  const outputPath = outputArg ? outputArg.split('=')[1] : undefined;

  exportCheckpoints({ stationId, outputPath })
    .then((path) => {
      console.log(`Export completed: ${path}`);
      process.exit(0);
    })
    .catch((err) => {
      console.error('[FATAL] Checkpoint export failed:', err);
      process.exit(1);
    });
}
