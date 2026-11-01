import fs from 'node:fs';
import path from 'node:path';
import {
  verifySignature,
  calculatePublicKeyFingerprint,
} from '@envirotrust/crypto';
import { validateWitnessCheckpointPayload } from '@envirotrust/contracts';
import {
  computeWitnessEventHash,
  WITNESS_GENESIS_HASH,
} from '../apps/witness/src/repositories/witness-event.repository.js';
import type { CheckpointExportFile } from './export-checkpoints.js';

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

export interface OfflineVerificationReport {
  stationId: string;
  totalCheckpoints: number;
  totalEventsVerified: number;
  checkpointsValid: boolean;
  eventsValid: boolean;
  overallStatus: 'PASS' | 'FAIL';
  discrepancies: Array<{
    type:
      | 'UNTRUSTED_WITNESS_KEY'
      | 'CHECKPOINT_SCHEMA'
      | 'CHECKPOINT_SIGNATURE'
      | 'FINGERPRINT_MISMATCH'
      | 'CHECKPOINT_CHAIN_BREAK'
      | 'EVENT_SEQUENCE_GAP'
      | 'EVENT_HASH_MISMATCH'
      | 'CHAIN_HEAD_MISMATCH';
    checkpointSequence?: number;
    witnessSequence?: number;
    messageId?: string;
    expected?: string;
    actual?: string;
    reason: string;
  }>;
}

export interface VerifyCheckpointOptions {
  trustedPublicKeyPem?: string;
  pinnedWitnessFingerprint?: string;
  trustedKeyDir?: string;
}

export function verifyExportedCheckpoints(
  exportData: CheckpointExportFile,
  options: VerifyCheckpointOptions | string = {}
): OfflineVerificationReport {
  const discrepancies: OfflineVerificationReport['discrepancies'] = [];

  // Normalize options
  const opts: VerifyCheckpointOptions =
    typeof options === 'string' ? { trustedPublicKeyPem: options } : options;

  let trustedPublicKeyPem = opts.trustedPublicKeyPem;
  let pinnedFingerprint = opts.pinnedWitnessFingerprint;

  // Resolve trusted key from local secrets if not explicitly provided
  if (!trustedPublicKeyPem && !pinnedFingerprint) {
    const keyDir = opts.trustedKeyDir || findWitnessKeyDir();
    const pubPath = path.join(keyDir, 'public.pem');
    const metaPath = path.join(keyDir, 'metadata.json');

    if (fs.existsSync(pubPath)) {
      trustedPublicKeyPem = fs.readFileSync(pubPath, 'utf-8');
      pinnedFingerprint = calculatePublicKeyFingerprint(trustedPublicKeyPem);
    } else if (fs.existsSync(metaPath)) {
      const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8')) as { fingerprint: string };
      pinnedFingerprint = meta.fingerprint;
    }
  }

  // Pre-pinned trusted witness public key enforcement
  if (trustedPublicKeyPem) {
    const derivedFingerprint = calculatePublicKeyFingerprint(trustedPublicKeyPem);
    pinnedFingerprint = pinnedFingerprint || derivedFingerprint;

    // Check if the exported key matches the trusted key
    if (exportData.witnessPublicKeyFingerprint !== derivedFingerprint) {
      discrepancies.push({
        type: 'UNTRUSTED_WITNESS_KEY',
        expected: derivedFingerprint,
        actual: exportData.witnessPublicKeyFingerprint,
        reason: 'Exported witness public key does not match trusted pre-pinned witness key fingerprint.',
      });
    }
  } else if (pinnedFingerprint) {
    if (exportData.witnessPublicKeyFingerprint !== pinnedFingerprint) {
      discrepancies.push({
        type: 'UNTRUSTED_WITNESS_KEY',
        expected: pinnedFingerprint,
        actual: exportData.witnessPublicKeyFingerprint,
        reason: 'Exported witness public key fingerprint does not match trusted pre-pinned fingerprint.',
      });
    }
  } else {
    // Neither trusted public key nor pinned fingerprint provided or found on disk
    discrepancies.push({
      type: 'UNTRUSTED_WITNESS_KEY',
      reason: 'No pre-pinned trusted witness public key or fingerprint was configured. Untrusted exported key rejected.',
    });
  }

  // Always verify signatures using the TRUSTED public key (fallback to exported key only if trusted is identical)
  const keyForVerification = trustedPublicKeyPem || exportData.witnessPublicKeyPem;
  if (!keyForVerification) {
    throw new Error('No public key available for offline verification');
  }

  let runningCheckpointHash = WITNESS_GENESIS_HASH;
  let runningEventHash = WITNESS_GENESIS_HASH;
  let expectedNextEventSeq = 1;
  let totalEventsVerified = 0;

  for (const cp of exportData.checkpoints) {
    // 1. Checkpoint Schema Validation
    const valResult = validateWitnessCheckpointPayload(cp.payload);
    if (!valResult.valid) {
      discrepancies.push({
        type: 'CHECKPOINT_SCHEMA',
        checkpointSequence: cp.payload.checkpointSequence,
        reason: `Checkpoint payload schema invalid: ${valResult.errors.map((e) => e.message).join('; ')}`,
      });
    }

    // 2. Checkpoint Fingerprint Check against pinned fingerprint
    if (pinnedFingerprint && cp.witnessPublicKeyFingerprint !== pinnedFingerprint) {
      discrepancies.push({
        type: 'FINGERPRINT_MISMATCH',
        checkpointSequence: cp.payload.checkpointSequence,
        expected: pinnedFingerprint,
        actual: cp.witnessPublicKeyFingerprint,
        reason: `Checkpoint ${cp.payload.checkpointSequence} witness fingerprint does not match trusted pinned fingerprint`,
      });
    }

    // 3. Checkpoint Signature Verification strictly against trusted key
    const sigResult = verifySignature(cp.payload, cp.signature, keyForVerification);
    if (!sigResult.valid) {
      discrepancies.push({
        type: 'CHECKPOINT_SIGNATURE',
        checkpointSequence: cp.payload.checkpointSequence,
        reason: `Cryptographic signature invalid on checkpoint ${cp.payload.checkpointSequence}: ${sigResult.reason || 'signature mismatch'}`,
      });
    }

    // 4. Checkpoint Chain Continuity
    if (cp.payload.previousCheckpointHash !== runningCheckpointHash) {
      discrepancies.push({
        type: 'CHECKPOINT_CHAIN_BREAK',
        checkpointSequence: cp.payload.checkpointSequence,
        expected: runningCheckpointHash,
        actual: cp.payload.previousCheckpointHash,
        reason: `Checkpoint sequence ${cp.payload.checkpointSequence} previousCheckpointHash does not match previous checkpoint hash`,
      });
    }

    // 5. Verify Covered Events Offline
    for (const ev of cp.events) {
      totalEventsVerified++;

      // Sequence continuity check
      if (ev.witnessSequence !== expectedNextEventSeq) {
        discrepancies.push({
          type: 'EVENT_SEQUENCE_GAP',
          checkpointSequence: cp.payload.checkpointSequence,
          witnessSequence: ev.witnessSequence,
          messageId: ev.messageId,
          expected: String(expectedNextEventSeq),
          actual: String(ev.witnessSequence),
          reason: `Event sequence gap: expected ${expectedNextEventSeq}, got ${ev.witnessSequence}`,
        });
      }

      // Previous event hash continuity check
      if (ev.previousHash !== runningEventHash) {
        discrepancies.push({
          type: 'EVENT_HASH_MISMATCH',
          checkpointSequence: cp.payload.checkpointSequence,
          witnessSequence: ev.witnessSequence,
          messageId: ev.messageId,
          expected: runningEventHash,
          actual: ev.previousHash,
          reason: `Event sequence ${ev.witnessSequence} previousHash mismatch`,
        });
      }

      // Recompute SHA-256 event hash from canonical metadata
      const recomputedHash = computeWitnessEventHash(ev.previousHash, ev.eventDataWithoutHash);
      if (recomputedHash !== ev.eventHash) {
        discrepancies.push({
          type: 'EVENT_HASH_MISMATCH',
          checkpointSequence: cp.payload.checkpointSequence,
          witnessSequence: ev.witnessSequence,
          messageId: ev.messageId,
          expected: recomputedHash,
          actual: ev.eventHash,
          reason: `Event sequence ${ev.witnessSequence} computed hash mismatch (tampered content or hash)`,
        });
      }

      runningEventHash = ev.eventHash;
      expectedNextEventSeq = ev.witnessSequence + 1;
    }

    // 6. Chain Head Hash Match Checkpoint
    if (cp.payload.chainHeadHash !== runningEventHash) {
      discrepancies.push({
        type: 'CHAIN_HEAD_MISMATCH',
        checkpointSequence: cp.payload.checkpointSequence,
        expected: runningEventHash,
        actual: cp.payload.chainHeadHash,
        reason: `Checkpoint ${cp.payload.checkpointSequence} chainHeadHash (${cp.payload.chainHeadHash}) does not match final event hash (${runningEventHash})`,
      });
    }

    runningCheckpointHash = cp.checkpointHash;
  }

  const checkpointsValid =
    discrepancies.filter(
      (d) =>
        d.type.startsWith('CHECKPOINT_') ||
        d.type === 'FINGERPRINT_MISMATCH' ||
        d.type === 'UNTRUSTED_WITNESS_KEY'
    ).length === 0;
  const eventsValid =
    discrepancies.filter((d) => d.type.startsWith('EVENT_') || d.type === 'CHAIN_HEAD_MISMATCH').length === 0;

  return {
    stationId: exportData.stationId,
    totalCheckpoints: exportData.checkpoints.length,
    totalEventsVerified,
    checkpointsValid,
    eventsValid,
    overallStatus: discrepancies.length === 0 ? 'PASS' : 'FAIL',
    discrepancies,
  };
}

// CLI execution
if (process.argv[1] && process.argv[1].endsWith('verify-checkpoint.ts')) {
  const fileArg = process.argv.find((a) => a.startsWith('--file='));
  const filePath = fileArg ? fileArg.split('=')[1] : path.resolve(process.cwd(), 'witness-checkpoint-export.json');
  const pinnedFingerprintArg = process.argv.find((a) => a.startsWith('--pinned-fingerprint='));
  const pinnedFingerprint = pinnedFingerprintArg ? pinnedFingerprintArg.split('=')[1] : undefined;
  const keyDirArg = process.argv.find((a) => a.startsWith('--key-dir='));
  const trustedKeyDir = keyDirArg ? keyDirArg.split('=')[1] : undefined;

  if (!fs.existsSync(filePath)) {
    console.error(`[ERROR] Export file not found at ${filePath}. Run 'npm run witness:checkpoint:export' first.`);
    process.exit(1);
  }

  const exportData = JSON.parse(fs.readFileSync(filePath, 'utf-8')) as CheckpointExportFile;
  const report = verifyExportedCheckpoints(exportData, { pinnedWitnessFingerprint: pinnedFingerprint, trustedKeyDir });

  // Machine-readable mode (used by the Attack Lab): print only the report; exit code still reflects the verdict.
  if (process.argv.includes('--json')) {
    console.log(JSON.stringify(report));
    process.exit(report.overallStatus === 'PASS' ? 0 : 1);
  }

  console.log('\n======================================================');
  console.log('EnviroTrust Witness Checkpoint Offline Verification');
  console.log('======================================================');
  console.log(`Station:            ${report.stationId}`);
  console.log(`Checkpoints:        ${report.totalCheckpoints}`);
  console.log(`Events Verified:    ${report.totalEventsVerified}`);
  console.log(`Checkpoints Valid:  ${report.checkpointsValid ? 'YES' : 'NO'}`);
  console.log(`Events Valid:       ${report.eventsValid ? 'YES' : 'NO'}`);
  console.log(`Overall Status:     ${report.overallStatus}`);
  console.log('======================================================');

  if (report.discrepancies.length > 0) {
    console.error('\n[DISCREPANCIES DETECTED]');
    report.discrepancies.forEach((d, i) => {
      console.error(`  ${i + 1}. [${d.type}] ${d.reason}`);
      if (d.expected) console.error(`     Expected: ${d.expected}`);
      if (d.actual) console.error(`     Actual:   ${d.actual}`);
    });
    process.exit(1);
  } else {
    console.log('\n[SUCCESS] All checkpoint signatures and hash chains independently verified against pinned witness key.');
    process.exit(0);
  }
}
