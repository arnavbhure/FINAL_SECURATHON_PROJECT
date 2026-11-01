import crypto from 'node:crypto';
import { canonicalizePayload } from './canonicalize.js';
import type { VerificationResult } from './types.js';

// Base64 regex for strict encoding validation
const STRICT_BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * Validates Base64 signature encoding strictly.
 * Checks format, padding, round-trip fidelity, and Ed25519 length (strictly 64 raw bytes).
 */
export function validateSignatureEncoding(signatureBase64: string): {
  valid: boolean;
  buffer?: Buffer;
  error?: string;
} {
  if (typeof signatureBase64 !== 'string' || signatureBase64.length === 0) {
    return { valid: false, error: 'Signature must be a non-empty string' };
  }

  const trimmed = signatureBase64.trim();
  if (trimmed.length < 80 || trimmed.length > 256) {
    return { valid: false, error: `Invalid signature string length: ${trimmed.length} chars (expected 80-256)` };
  }

  if (trimmed.length % 4 !== 0 || !STRICT_BASE64_REGEX.test(trimmed)) {
    return { valid: false, error: 'Signature has invalid Base64 format or padding' };
  }

  let buffer: Buffer;
  try {
    buffer = Buffer.from(trimmed, 'base64');
  } catch {
    return { valid: false, error: 'Failed to decode Base64 signature' };
  }

  // Strict check: Buffer round-trip must equal trimmed string
  if (buffer.toString('base64') !== trimmed) {
    return { valid: false, error: 'Signature fails strict Base64 round-trip validation' };
  }

  // Ed25519 signatures are strictly 64 raw bytes (RFC 8032)
  if (buffer.length !== 64) {
    return { valid: false, error: `Invalid Ed25519 signature byte length: ${buffer.length} bytes (expected 64 bytes)` };
  }

  return { valid: true, buffer };
}

/**
 * Verifies an Ed25519 digital signature over an RFC 8785 canonicalized payload.
 *
 * @param payload - The complete payload object originally signed
 * @param signatureBase64 - Base64-encoded signature
 * @param publicKeyPem - Ed25519 public key in SPKI PEM format
 * @returns boolean indicating whether the signature is mathematically valid
 */
export function verifyPayloadSignature(
  payload: unknown,
  signatureBase64: string,
  publicKeyPem: string
): boolean {
  return verifyPayloadSignatureWithReason(payload, signatureBase64, publicKeyPem).valid;
}

/**
 * Verifies an Ed25519 digital signature and returns a structured outcome with reason.
 */
export function verifyPayloadSignatureWithReason(
  payload: unknown,
  signatureBase64: string,
  publicKeyPem: string
): VerificationResult {
  if (typeof payload !== 'object' || payload === null) {
    return { valid: false, reason: 'Payload must be a non-null object' };
  }

  if (!publicKeyPem || typeof publicKeyPem !== 'string') {
    return { valid: false, reason: 'Public key PEM must be a non-empty string' };
  }

  // 1. Strict signature encoding and length check
  const encodingCheck = validateSignatureEncoding(signatureBase64);
  if (!encodingCheck.valid || !encodingCheck.buffer) {
    return { valid: false, reason: encodingCheck.error || 'Invalid signature encoding' };
  }

  // 2. Validate public key format
  let keyObj: crypto.KeyObject;
  try {
    keyObj = crypto.createPublicKey(publicKeyPem);
    if (keyObj.asymmetricKeyType !== 'ed25519') {
      return { valid: false, reason: `Invalid public key algorithm: expected ed25519, got ${keyObj.asymmetricKeyType}` };
    }
  } catch (err) {
    return { valid: false, reason: `Failed to parse public key PEM: ${(err as Error).message}` };
  }

  // 3. Canonicalize payload identically to signer
  let canonicalBytes: Buffer;
  try {
    const canonicalString = canonicalizePayload(payload);
    canonicalBytes = Buffer.from(canonicalString, 'utf-8');
  } catch (err) {
    return { valid: false, reason: `Failed to canonicalize payload: ${(err as Error).message}` };
  }

  // 4. Verify signature with Node.js crypto
  try {
    const isValid = crypto.verify(null, canonicalBytes, keyObj, encodingCheck.buffer);
    if (!isValid) {
      return { valid: false, reason: 'Cryptographic signature mismatch: payload was modified or signed by a different key' };
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, reason: `Verification error: ${(err as Error).message}` };
  }
}

export const verifySignature = verifyPayloadSignatureWithReason;

