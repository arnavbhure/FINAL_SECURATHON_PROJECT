-- Migration 001: Initial Witness Schema
-- Independent Witness storage for EnviroTrust
-- Uses separate database credentials and isolated storage from primary API.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

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

CREATE TABLE IF NOT EXISTS witness_operations_keys (
  key_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL,
  site_code TEXT NOT NULL,
  station_code TEXT NOT NULL,
  algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
  public_key_pem TEXT NOT NULL,
  fingerprint_sha256 CHAR(64) NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
  provisioned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS witness_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  witness_sequence BIGINT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('TELEMETRY', 'OPERATIONS_CONTEXT')),
  message_id UUID NOT NULL UNIQUE,
  site_code TEXT NOT NULL,
  station_code TEXT NOT NULL,
  identity_type TEXT NOT NULL CHECK (identity_type IN ('SENSOR', 'OPERATIONS_SOURCE')),
  identity_code TEXT NOT NULL,
  key_id TEXT NOT NULL,
  boot_id TEXT,
  source_sequence BIGINT NOT NULL,
  source_timestamp TIMESTAMPTZ NOT NULL,
  payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  signature_hash CHAR(64) NOT NULL,
  witness_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  previous_hash CHAR(64) NOT NULL,
  event_hash CHAR(64) NOT NULL,
  UNIQUE (station_code, witness_sequence)
);

CREATE INDEX IF NOT EXISTS idx_witness_events_station_seq ON witness_events(station_code, witness_sequence ASC);
CREATE INDEX IF NOT EXISTS idx_witness_events_message ON witness_events(message_id);

CREATE TABLE IF NOT EXISTS witness_chain_cursors (
  station_code TEXT PRIMARY KEY,
  last_witness_sequence BIGINT NOT NULL DEFAULT 0,
  chain_head_hash CHAR(64) NOT NULL,
  last_checkpoint_sequence BIGINT NOT NULL DEFAULT 0,
  last_checkpoint_hash CHAR(64),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS witness_checkpoints (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  witness_id TEXT NOT NULL,
  witness_key_id TEXT NOT NULL,
  site_code TEXT NOT NULL,
  station_code TEXT NOT NULL,
  checkpoint_sequence BIGINT NOT NULL,
  last_witness_sequence BIGINT NOT NULL,
  chain_head_hash CHAR(64) NOT NULL,
  previous_checkpoint_hash CHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  canonical_payload TEXT NOT NULL,
  signature_base64 TEXT NOT NULL,
  checkpoint_hash CHAR(64) NOT NULL,
  witness_public_key_fingerprint CHAR(64) NOT NULL,
  UNIQUE (station_code, checkpoint_sequence)
);

CREATE INDEX IF NOT EXISTS idx_witness_checkpoints_station ON witness_checkpoints(station_code, checkpoint_sequence DESC);

CREATE TABLE IF NOT EXISTS witness_security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  sanitized_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

