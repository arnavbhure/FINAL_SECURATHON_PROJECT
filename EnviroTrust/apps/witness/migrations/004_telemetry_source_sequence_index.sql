-- Migration 004: Lookup index for telemetry source-sequence uniqueness checks
-- The witness rejects a new telemetry message that reuses an already witnessed
-- (sensor, bootId, sequence) tuple (docs/05_INDEPENDENT_WITNESS.md §4 step 6).
-- The check runs in code under the station cursor lock; this index keeps it cheap.

CREATE INDEX IF NOT EXISTS idx_witness_events_source_sequence
  ON witness_events (identity_code, boot_id, source_sequence)
  WHERE event_type = 'TELEMETRY';
