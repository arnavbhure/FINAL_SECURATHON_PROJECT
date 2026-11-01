-- Migration 002: Sequence Cursors and Audit State Tracking
-- Provides transactional tracking of sequence numbers and audit hash chains per entity.

CREATE TABLE IF NOT EXISTS sensor_sequence_cursors (
  sensor_id UUID PRIMARY KEY REFERENCES sensors(id),
  boot_id TEXT NOT NULL,
  last_sequence_no BIGINT NOT NULL,
  last_measured_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS operations_sequence_cursors (
  source_id TEXT PRIMARY KEY,
  last_sequence_no BIGINT NOT NULL,
  last_interval_end TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS station_audit_cursors (
  station_id UUID PRIMARY KEY REFERENCES monitoring_stations(id),
  last_event_sequence BIGINT NOT NULL DEFAULT 0,
  chain_head_hash CHAR(64) NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

