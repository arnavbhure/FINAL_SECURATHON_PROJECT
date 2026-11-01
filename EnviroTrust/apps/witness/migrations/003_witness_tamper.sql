-- Migration 003: Witness Tamper Events and Expanded Event Types
-- Independent Witness storage for EnviroTrust Physical Tamper Ingestion

CREATE TABLE IF NOT EXISTS witness_tamper_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL UNIQUE,
  sensor_code TEXT NOT NULL,
  site_code TEXT NOT NULL,
  station_code TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES witness_sensor_keys(key_id),
  event_type TEXT NOT NULL CHECK (event_type IN ('ENCLOSURE_OPENED', 'PHYSICAL_INTERFERENCE', 'DEVICE_MOVEMENT')),
  event_timestamp TIMESTAMPTZ NOT NULL,
  tamper_source TEXT NOT NULL,
  sequence_no BIGINT NOT NULL,
  payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  signature_hash CHAR(64) NOT NULL,
  witness_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (sensor_code, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_witness_tamper_sensor ON witness_tamper_events(sensor_code, witness_received_at DESC);
CREATE INDEX IF NOT EXISTS idx_witness_tamper_event ON witness_tamper_events(event_id);

-- Update check constraint on witness_events to allow 'PHYSICAL_TAMPER'
ALTER TABLE witness_events DROP CONSTRAINT IF EXISTS witness_events_event_type_check;
ALTER TABLE witness_events ADD CONSTRAINT witness_events_event_type_check
  CHECK (event_type IN ('TELEMETRY', 'OPERATIONS_CONTEXT', 'HEARTBEAT', 'PHYSICAL_TAMPER'));

