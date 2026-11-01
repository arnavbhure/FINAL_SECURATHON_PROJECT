import crypto from 'node:crypto';
import { canonicalizePayload } from './canonicalize.js';

/**
 * Signs a payload using RFC 8785 JSON canonicalization and Ed25519 digital signature.
 *
 * @param payload - The complete payload object to sign
 * @param privateKeyPem - The Ed25519 private key in PKCS8 PEM format
 * @returns Base64-encoded Ed25519 signature
 * @throws Error if canonicalization or signing fails
 */
export function signPayload(payload: unknown, privateKeyPem: string): string {
  if (typeof payload !== 'object' || payload === null) {
    throw new Error('Payload to sign must be a non-null object');
  }

  if (!privateKeyPem || typeof privateKeyPem !== 'string') {
    throw new Error('Private key PEM must be a non-empty string');
  }

  const keyObj = crypto.createPrivateKey(privateKeyPem);
  if (keyObj.asymmetricKeyType !== 'ed25519') {
    throw new Error(`Invalid private key algorithm: expected ed25519, got ${keyObj.asymmetricKeyType}`);
  }

  // Canonicalize the complete payload object
  const canonicalString = canonicalizePayload(payload);
  const canonicalBytes = Buffer.from(canonicalString, 'utf-8');

  // Sign with null algorithm parameter (Ed25519 incorporates its own hashing)
  const signatureBytes = crypto.sign(null, canonicalBytes, keyObj);

  return signatureBytes.toString('base64');
}

