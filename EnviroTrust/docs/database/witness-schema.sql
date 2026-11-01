-- EnviroTrust witness database reference schema.
-- Use separate database credentials/storage from the primary application.

CREATE TABLE IF NOT EXISTS witness_sensor_keys (
  key_id TEXT PRIMARY KEY,
  sensor_code TEXT NOT NULL,
  site_code TEXT NOT NULL,
  station_code TEXT NOT NULL,
  parameter TEXT NOT NULL,
  public_key_pem TEXT NOT NULL,
  fingerprint_sha256 CHAR(64) NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
  provisioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS witness_events (
  id UUID PRIMARY KEY,
  witness_sequence BIGINT NOT NULL,
  message_id UUID NOT NULL UNIQUE,
  site_code TEXT NOT NULL,
  station_code TEXT NOT NULL,
  sensor_code TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES witness_sensor_keys(key_id),
  boot_id TEXT NOT NULL,
  sensor_sequence BIGINT NOT NULL,
  payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  witness_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  previous_hash CHAR(64),
  event_hash CHAR(64) NOT NULL,
  UNIQUE (sensor_code, boot_id, sensor_sequence),
  UNIQUE (station_code, witness_sequence)
);

CREATE TABLE IF NOT EXISTS witness_heartbeats (
  id UUID PRIMARY KEY,
  message_id UUID NOT NULL UNIQUE,
  sensor_code TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES witness_sensor_keys(key_id),
  boot_id TEXT NOT NULL,
  heartbeat_sequence BIGINT NOT NULL,
  sent_at TIMESTAMPTZ NOT NULL,
  witness_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  signature_base64 TEXT NOT NULL,
  UNIQUE (sensor_code, boot_id, heartbeat_sequence)
);

CREATE TABLE IF NOT EXISTS witness_checkpoints (
  id UUID PRIMARY KEY,
  witness_id TEXT NOT NULL,
  station_code TEXT NOT NULL,
  checkpoint_sequence BIGINT NOT NULL,
  last_witness_sequence BIGINT NOT NULL,
  chain_head_hash CHAR(64) NOT NULL,
  previous_checkpoint_hash CHAR(64),
  created_at TIMESTAMPTZ NOT NULL,
  canonical_payload TEXT NOT NULL,
  signature_base64 TEXT NOT NULL,
  checkpoint_hash CHAR(64) NOT NULL,
  UNIQUE (station_code, checkpoint_sequence)
);
