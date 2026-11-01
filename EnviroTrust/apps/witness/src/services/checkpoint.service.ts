import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  canonicalizePayload,
  signPayload,
  verifySignature,
  calculatePublicKeyFingerprint,
} from '@envirotrust/crypto';
import {
  validateWitnessCheckpointPayload,
  type WitnessCheckpointPayload,
  type SignedWitnessCheckpoint,
} from '@envirotrust/contracts';

export interface WitnessKeyInfo {
  witnessId: string;
  keyId: string;
  displayName: string;
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
}

export interface CreatedCheckpoint {
  payload: WitnessCheckpointPayload;
  canonicalPayload: string;
  signature: string;
  checkpointHash: string;
  witnessPublicKeyFingerprint: string;
}

export class CheckpointService {
  private keyInfo: WitnessKeyInfo | null = null;

  constructor(private readonly keyDir: string) {}

  public loadKeyInfo(): WitnessKeyInfo {
    if (this.keyInfo) {
      return this.keyInfo;
    }

    const resolvedDir = path.resolve(this.keyDir);
    const metadataPath = path.join(resolvedDir, 'metadata.json');
    const privateKeyPath = path.join(resolvedDir, 'private.pem');
    const publicKeyPath = path.join(resolvedDir, 'public.pem');

    if (!fs.existsSync(metadataPath) || !fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
      throw new Error(`Witness keys not found at ${resolvedDir}. Run 'npm run witness:keys:provision' first.`);
    }

    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8')) as {
      witnessId: string;
      keyId: string;
      displayName: string;
      fingerprint: string;
    };
    const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf-8');
    const publicKeyPem = fs.readFileSync(publicKeyPath, 'utf-8');

    const calculatedFingerprint = calculatePublicKeyFingerprint(publicKeyPem);
    if (metadata.fingerprint && metadata.fingerprint !== calculatedFingerprint) {
      throw new Error(
        `Witness public key fingerprint mismatch! Expected ${metadata.fingerprint}, got ${calculatedFingerprint}`
      );
    }

    this.keyInfo = {
      witnessId: metadata.witnessId,
      keyId: metadata.keyId,
      displayName: metadata.displayName,
      publicKeyPem,
      privateKeyPem,
      fingerprint: calculatedFingerprint,
    };

    return this.keyInfo;
  }

  public getPublicKeyPem(): string {
    return this.loadKeyInfo().publicKeyPem;
  }

  public getPublicKeyFingerprint(): string {
    return this.loadKeyInfo().fingerprint;
  }

  /**
   * Constructs, validates, canonicalizes, and signs a new witness checkpoint.
   */
  public createSignedCheckpoint(params: {
    siteId: string;
    stationId: string;
    checkpointSequence: number;
    lastWitnessSequence: number;
    chainHeadHash: string;
    previousCheckpointHash: string;
    checkpointId?: string;
    createdAt?: string;
  }): CreatedCheckpoint {
    const key = this.loadKeyInfo();

    const payload: WitnessCheckpointPayload = {
      schemaVersion: 1,
      checkpointId: params.checkpointId || crypto.randomUUID(),
      witnessId: key.witnessId,
      witnessKeyId: key.keyId,
      siteId: params.siteId,
      stationId: params.stationId,
      checkpointSequence: params.checkpointSequence,
      lastWitnessSequence: params.lastWitnessSequence,
      chainHeadHash: params.chainHeadHash.toLowerCase(),
      previousCheckpointHash: params.previousCheckpointHash.toLowerCase(),
      createdAt: params.createdAt || new Date().toISOString(),
    };

    // Validate payload against JSON schema
    const validation = validateWitnessCheckpointPayload(payload);
    if (!validation.valid) {
      const errMsgs = validation.errors.map((e) => `${e.path} ${e.message}`).join('; ');
      throw new Error(`Invalid checkpoint payload structure: ${errMsgs}`);
    }

    // Canonicalize RFC 8785
    const canonicalPayload = canonicalizePayload(payload);

    // Sign with Ed25519
    const signature = signPayload(payload, key.privateKeyPem);

    // Checkpoint hash: SHA256 of canonical payload
    const checkpointHash = crypto
      .createHash('sha256')
      .update(canonicalPayload, 'utf-8')
      .digest('hex')
      .toLowerCase();

    return {
      payload,
      canonicalPayload,
      signature,
      checkpointHash,
      witnessPublicKeyFingerprint: key.fingerprint,
    };
  }

  /**
   * Verifies a signed witness checkpoint against the expected public key.
   */
  public verifyCheckpoint(
    checkpoint: SignedWitnessCheckpoint,
    expectedPublicKeyPem?: string
  ): { valid: boolean; reason?: string } {
    const publicKeyPem = expectedPublicKeyPem || this.getPublicKeyPem();

    // 1. Validate payload schema
    const validation = validateWitnessCheckpointPayload(checkpoint.payload);
    if (!validation.valid) {
      return {
        valid: false,
        reason: `Schema validation failed: ${validation.errors.map((e) => e.message).join('; ')}`,
      };
    }

    // 2. Validate fingerprint binding
    const expectedFingerprint = calculatePublicKeyFingerprint(publicKeyPem);
    if (checkpoint.witnessPublicKeyFingerprint !== expectedFingerprint) {
      return {
        valid: false,
        reason: `Fingerprint mismatch: expected ${expectedFingerprint}, got ${checkpoint.witnessPublicKeyFingerprint}`,
      };
    }

    // 3. Verify digital signature
    const sigResult = verifySignature(checkpoint.payload, checkpoint.signature, publicKeyPem);
    if (!sigResult.valid) {
      return {
        valid: false,
        reason: `Signature verification failed: ${sigResult.reason || 'invalid signature'}`,
      };
    }

    return { valid: true };
  }
}
