import canonicalizePkg from 'canonicalize';

const canonicalize = ((canonicalizePkg as unknown as { default?: (val: unknown) => string | undefined }).default ||
  canonicalizePkg) as (val: unknown) => string | undefined;

/**
 * Canonicalizes a payload object according to RFC 8785 JSON Canonicalization Scheme (JCS).
 * Ensures deterministic property ordering and formatting.
 *
 * @param payload - The data structure to canonicalize
 * @returns UTF-8 canonical JSON string
 * @throws Error if payload is invalid, undefined, or cannot be serialized
 */
export function canonicalizePayload(payload: unknown): string {
  if (payload === undefined || payload === null) {
    throw new Error('Cannot canonicalize null or undefined payload');
  }

  if (typeof payload !== 'object') {
    throw new Error(`Cannot canonicalize non-object payload: ${typeof payload}`);
  }

  const result = canonicalize(payload);
  if (typeof result !== 'string') {
    throw new Error('RFC 8785 canonicalization failed: result is not a string');
  }

  return result;
}

