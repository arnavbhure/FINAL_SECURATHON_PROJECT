-- Migration 002: Witness Heartbeats, Operations Cursors, and Expanded Event Types
-- Independent Witness storage for EnviroTrust Prompt 5

-- 1. Operations context sequence cursors in witness
CREATE TABLE IF NOT EXISTS witness_operations_cursors (
  source_id TEXT PRIMARY KEY,
  last_sequence BIGINT NOT NULL,
  last_interval_end TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Heartbeats storage in witness
CREATE TABLE IF NOT EXISTS witness_heartbeats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id UUID NOT NULL UNIQUE,
  sensor_code TEXT NOT NULL,
  site_code TEXT NOT NULL,
  station_code TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES witness_sensor_keys(key_id),
  boot_id TEXT NOT NULL,
  heartbeat_sequence BIGINT NOT NULL,
  sent_at TIMESTAMPTZ NOT NULL,
  witness_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  signature_hash CHAR(64) NOT NULL,
  UNIQUE (sensor_code, boot_id, heartbeat_sequence)
);

CREATE INDEX IF NOT EXISTS idx_witness_heartbeats_sensor ON witness_heartbeats(sensor_code, witness_received_at DESC);
CREATE INDEX IF NOT EXISTS idx_witness_heartbeats_message ON witness_heartbeats(message_id);

-- 3. Heartbeat sequence cursors in witness
CREATE TABLE IF NOT EXISTS witness_heartbeat_cursors (
  sensor_code TEXT PRIMARY KEY,
  boot_id TEXT NOT NULL,
  last_heartbeat_sequence BIGINT NOT NULL,
  last_sent_at TIMESTAMPTZ NOT NULL,
  last_received_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. Update check constraint on witness_events to allow 'HEARTBEAT'
ALTER TABLE witness_events DROP CONSTRAINT IF EXISTS witness_events_event_type_check;
ALTER TABLE witness_events ADD CONSTRAINT witness_events_event_type_check
  CHECK (event_type IN ('TELEMETRY', 'OPERATIONS_CONTEXT', 'HEARTBEAT'));

