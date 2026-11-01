-- Migration 004: Primary Heartbeat Cursors and Indexing
-- Dedicated sequence tracking for sensor heartbeats (isolated from telemetry cursors)

CREATE TABLE IF NOT EXISTS sensor_heartbeat_cursors (
  sensor_id UUID PRIMARY KEY REFERENCES sensors(id),
  boot_id TEXT NOT NULL,
  last_heartbeat_sequence BIGINT NOT NULL,
  last_sent_at TIMESTAMPTZ NOT NULL,
  last_received_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_heartbeats_sensor_received ON heartbeats(sensor_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_heartbeats_message ON heartbeats(message_id);

