import type { HttpExchange } from './types.js';

const MAX_BODY_CHARS = 4000;

function boundBody(body: unknown): unknown {
  if (body === undefined || body === null) return null;
  const text = JSON.stringify(body);
  if (text.length <= MAX_BODY_CHARS) return body;
  return { truncated: true, preview: text.slice(0, MAX_BODY_CHARS) };
}

/**
 * Performs one real HTTP request against a demo service and records the exchange.
 * Request headers (which may carry service tokens) are never recorded.
 */
export async function exchange(
  target: HttpExchange['target'],
  baseUrl: string,
  endpoint: string,
  options: {
    method?: 'GET' | 'POST';
    body?: unknown;
    headers?: Record<string, string>;
    timeoutMs?: number;
  } = {}
): Promise<HttpExchange> {
  const method = options.method || 'POST';
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 8000);

  try {
    const res = await fetch(`${baseUrl}${endpoint}`, {
      method,
      headers: {
        Accept: 'application/json',
        ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(options.headers || {}),
      },
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      signal: controller.signal,
    });
    const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    const requestId =
      (data && typeof data['requestId'] === 'string' ? (data['requestId'] as string) : null) ||
      res.headers.get('x-request-id');
    return {
      target,
      method,
      endpoint,
      status: res.status,
      ok: res.ok,
      code: data && typeof data['code'] === 'string' ? (data['code'] as string) : null,
      message: data && typeof data['message'] === 'string' ? (data['message'] as string) : null,
      requestId,
      body: boundBody(data),
      networkError: null,
      durationMs: Date.now() - started,
    };
  } catch (err) {
    const e = err as Error & { cause?: { code?: string } };
    return {
      target,
      method,
      endpoint,
      status: null,
      ok: false,
      code: null,
      message: null,
      requestId: null,
      body: null,
      networkError: e.name === 'AbortError' ? 'TIMEOUT' : e.cause?.code || e.message,
      durationMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Compact view of an exchange for step details and evidence summaries. */
export function describeExchange(ex: HttpExchange): string {
  if (ex.status === null) return `${ex.target} unreachable (${ex.networkError})`;
  return `${ex.target} HTTP ${ex.status}${ex.code ? ` ${ex.code}` : ''}`;
}
