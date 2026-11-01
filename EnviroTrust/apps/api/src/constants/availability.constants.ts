/**
 * Sensor availability and freshness constants.
 * Documented baseline values per specification pack.
 */

export const AVAILABILITY_CONSTANTS = {
  /** Expected interval between sensor heartbeats in seconds (default: 10s) */
  DEFAULT_HEARTBEAT_INTERVAL_SECONDS: 10,

  /** Number of missed intervals before marking sensor as STALE (2 intervals = 20s) */
  DEFAULT_STALE_INTERVALS: 2,

  /** Number of missed intervals before marking sensor as OFFLINE (3 intervals = 30s) */
  DEFAULT_OFFLINE_INTERVALS: 3,

  /** Maximum transit delay for a heartbeat to be eligible for current liveness (30s) */
  MAX_HEARTBEAT_AGE_SECONDS: 30,

  /** Maximum allowed forward clock skew in seconds (120s) */
  MAX_FUTURE_SKEW_SECONDS: 120,

  /** Maximum age for telemetry readings to be marked as FRESH (300s) */
  MAX_TELEMETRY_AGE_SECONDS: 300,
} as const;

