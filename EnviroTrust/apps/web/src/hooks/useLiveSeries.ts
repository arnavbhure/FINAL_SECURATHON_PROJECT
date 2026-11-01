import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

export interface LiveSeriesOptions<T> {
  /** Changing the key discards the buffered points and reloads the window (e.g. site or parameter switch). */
  key: string;
  /** Fetches points measured at or after `fromIso`. Order does not matter; points are merged by id. */
  fetchSince: (fromIso: string) => Promise<T[]>;
  getId: (point: T) => string;
  /** Epoch milliseconds of the point's physical measurement time. */
  getTime: (point: T) => number;
  /** Width of the sliding window kept in memory and shown on the chart. */
  windowMs: number;
  intervalMs?: number;
  /**
   * Each poll re-fetches this far behind the newest buffered point, so late deliveries and rows
   * updated after ingestion (e.g. ML assessments completing) replace their earlier copies.
   */
  lookbackMs?: number;
  maxPoints?: number;
  /** When false, polling stops but the buffered points are kept. */
  enabled?: boolean;
}

export interface LiveSeriesState<T> {
  points: T[];
  lastUpdated: Date | null;
  error: string | null;
  consecutiveFailures: number;
  /** True until the first successful fetch for the current key/window. */
  loading: boolean;
}

const MAX_BACKOFF_MS = 30_000;

/**
 * Continuously polls the backend for new time-series points and keeps a bounded,
 * chronologically sorted sliding window of them. On errors the last data is kept and
 * polling retries with exponential backoff. Timers and listeners are released on unmount.
 */
export function useLiveSeries<T>({
  key,
  fetchSince,
  getId,
  getTime,
  windowMs,
  intervalMs = 2000,
  lookbackMs = 120_000,
  maxPoints = 2000,
  enabled = true,
}: LiveSeriesOptions<T>): LiveSeriesState<T> & { pollNow: () => void } {
  const [state, setState] = useState<LiveSeriesState<T>>({
    points: [],
    lastUpdated: null,
    error: null,
    consecutiveFailures: 0,
    loading: true,
  });

  // Callers usually pass inline closures; keep the latest ones without restarting the poll loop.
  const fnRef = useRef({ fetchSince, getId, getTime });
  useLayoutEffect(() => {
    fnRef.current = { fetchSince, getId, getTime };
  });

  const bufferRef = useRef<Map<string, T>>(new Map());
  const bufferIdentityRef = useRef<string | null>(null);
  const pollNowRef = useRef<() => void>(() => {});

  useEffect(() => {
    // A new key or window width invalidates the buffer; pausing/resuming keeps it.
    const identity = `${key}|${windowMs}`;
    if (bufferIdentityRef.current !== identity) {
      bufferIdentityRef.current = identity;
      bufferRef.current = new Map();
      setState({ points: [], lastUpdated: null, error: null, consecutiveFailures: 0, loading: true });
    }

    if (!enabled) {
      pollNowRef.current = () => {};
      return;
    }

    let cancelled = false;
    let inFlight = false;
    let failures = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const schedule = (delayMs: number) => {
      clearTimeout(timer);
      timer = setTimeout(tick, delayMs);
    };

    async function tick() {
      if (cancelled || inFlight) return;
      if (document.visibilityState !== 'visible') {
        schedule(intervalMs);
        return;
      }

      const { fetchSince: fetchFn, getId: idOf, getTime: timeOf } = fnRef.current;
      const buffer = bufferRef.current;
      const windowStart = Date.now() - windowMs;
      let newest = -Infinity;
      for (const p of buffer.values()) {
        const t = timeOf(p);
        if (t > newest) newest = t;
      }
      const fromMs = Number.isFinite(newest) ? Math.max(windowStart, newest - lookbackMs) : windowStart;

      inFlight = true;
      try {
        const fresh = await fetchFn(new Date(fromMs).toISOString());
        if (cancelled) return;

        for (const p of fresh) buffer.set(idOf(p), p);

        // Keep a small margin past the left edge so lines slide out of view instead of popping.
        const cutoff = Date.now() - windowMs * 1.1;
        const sorted = Array.from(buffer.values())
          .filter((p) => {
            const t = timeOf(p);
            return Number.isFinite(t) && t >= cutoff;
          })
          .sort((a, b) => timeOf(a) - timeOf(b))
          .slice(-maxPoints);
        bufferRef.current = new Map(sorted.map((p) => [idOf(p), p]));

        failures = 0;
        setState({ points: sorted, lastUpdated: new Date(), error: null, consecutiveFailures: 0, loading: false });
        schedule(intervalMs);
      } catch (err) {
        if (cancelled) return;
        failures += 1;
        const message = err instanceof Error ? err.message : 'Live telemetry request failed';
        setState((prev) => ({ ...prev, error: message, consecutiveFailures: failures }));
        schedule(Math.min(intervalMs * 2 ** failures, MAX_BACKOFF_MS));
      } finally {
        inFlight = false;
      }
    }

    const pollNow = () => {
      if (!cancelled && !inFlight) {
        clearTimeout(timer);
        void tick();
      }
    };
    pollNowRef.current = pollNow;

    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') pollNow();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    void tick();

    return () => {
      cancelled = true;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
      pollNowRef.current = () => {};
    };
  }, [key, windowMs, enabled, intervalMs, lookbackMs, maxPoints]);

  const pollNow = useCallback(() => pollNowRef.current(), []);

  return { ...state, pollNow };
}
