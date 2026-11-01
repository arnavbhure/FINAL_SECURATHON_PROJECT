import crypto, { type KeyObject } from 'node:crypto';
import fs from 'node:fs';
import type { Ed25519KeyPair } from './types.js';

/**
 * Calculates a SHA-256 fingerprint from SPKI DER bytes of an Ed25519 public key.
 *
 * @param publicKey - PEM string, KeyObject, or DER Buffer
 * @returns 64-character lowercase hexadecimal SHA-256 fingerprint
 */
export function calculatePublicKeyFingerprint(publicKey: string | KeyObject | Buffer): string {
  let derBuffer: Buffer;

  if (Buffer.isBuffer(publicKey)) {
    derBuffer = publicKey;
  } else if (typeof publicKey === 'string') {
    const keyObj = crypto.createPublicKey(publicKey);
    derBuffer = keyObj.export({ type: 'spki', format: 'der' });
  } else {
    derBuffer = publicKey.export({ type: 'spki', format: 'der' });
  }

  return crypto.createHash('sha256').update(derBuffer).digest('hex').toLowerCase();
}

export const computePublicKeyFingerprint = calculatePublicKeyFingerprint;

/**
 * Generates an independent Ed25519 key pair using Node.js built-in crypto.
 * Returns PKCS8 PEM private key, SPKI PEM public key, and SHA-256 SPKI fingerprint.
 */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
  });

  const fingerprint = calculatePublicKeyFingerprint(publicKey);

  return {
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
    fingerprint,
  };
}

export interface JwtKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

/**
 * Generates an ECDSA P-256 (prime256v1) key pair for ES256 JWT signing and verification.
 */
export function generateJwtKeyPair(): JwtKeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
  });

  return {
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
  };
}

/**
 * Loads and validates an Ed25519 private key from a PEM file.
 *
 * @param filePath - Absolute or relative path to private key PEM
 * @returns Private key PEM string
 * @throws Error if file does not exist or key is not valid Ed25519
 */
export function loadPrivateKey(filePath: string): string {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Private key file not found at: ${filePath}`);
  }

  const pem = fs.readFileSync(filePath, 'utf-8');
  try {
    const keyObj = crypto.createPrivateKey(pem);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      throw new Error(`Invalid key type: expected ed25519, got ${keyObj.asymmetricKeyType}`);
    }
  } catch (err) {
    throw new Error(`Failed to parse Ed25519 private key from ${filePath}: ${(err as Error).message}`);
  }

  return pem;
}

/**
 * Loads and validates an Ed25519 public key from a PEM file.
 *
 * @param filePath - Absolute or relative path to public key PEM
 * @returns Public key PEM string
 * @throws Error if file does not exist or key is not valid Ed25519
 */
export function loadPublicKey(filePath: string): string {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Public key file not found at: ${filePath}`);
  }

  const pem = fs.readFileSync(filePath, 'utf-8');
  try {
    const keyObj = crypto.createPublicKey(pem);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      throw new Error(`Invalid key type: expected ed25519, got ${keyObj.asymmetricKeyType}`);
    }
  } catch (err) {
    throw new Error(`Failed to parse Ed25519 public key from ${filePath}: ${(err as Error).message}`);
  }

  return pem;
}

