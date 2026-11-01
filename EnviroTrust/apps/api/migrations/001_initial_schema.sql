-- Migration 001: Initial Primary Schema
-- EnviroTrust primary database reference schema
-- Applied via migration runner. Accepted telemetry and audit rows are append-only.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  global_role TEXT CHECK (global_role IN ('PLATFORM_ADMIN') OR global_role IS NULL),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  site_code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  industry_type TEXT NOT NULL,
  is_demo BOOLEAN NOT NULL DEFAULT TRUE,
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS site_memberships (
  user_id UUID NOT NULL REFERENCES users(id),
  site_id UUID NOT NULL REFERENCES sites(id),
  role TEXT NOT NULL CHECK (role IN ('FACTORY_OPERATOR','REGULATOR_AUDITOR')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, site_id, role)
);

CREATE TABLE IF NOT EXISTS monitoring_stations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id UUID NOT NULL REFERENCES sites(id),
  station_code TEXT NOT NULL,
  name TEXT NOT NULL,
  station_type TEXT NOT NULL DEFAULT 'ETP_OUTLET',
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (site_id, station_code)
);

CREATE TABLE IF NOT EXISTS sensors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sensor_code TEXT NOT NULL UNIQUE,
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  parameter TEXT NOT NULL CHECK (parameter IN ('pH','COD','TSS')),
  unit TEXT NOT NULL,
  expected_interval_seconds INTEGER NOT NULL DEFAULT 10 CHECK (expected_interval_seconds > 0),
  status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE','REVOKED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id TEXT NOT NULL UNIQUE,
  sensor_id UUID NOT NULL REFERENCES sensors(id),
  algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
  public_key_pem TEXT NOT NULL,
  fingerprint_sha256 CHAR(64) NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','REVOKED','EXPIRED')),
  valid_from TIMESTAMPTZ NOT NULL,
  valid_to TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS operations_source_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_id TEXT NOT NULL UNIQUE,
  source_id TEXT NOT NULL,
  site_id UUID NOT NULL REFERENCES sites(id),
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  algorithm TEXT NOT NULL CHECK (algorithm = 'Ed25519'),
  public_key_pem TEXT NOT NULL,
  fingerprint_sha256 CHAR(64) NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','REVOKED','EXPIRED')),
  valid_from TIMESTAMPTZ NOT NULL,
  valid_to TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS calibration_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sensor_id UUID NOT NULL REFERENCES sensors(id),
  calibration_code TEXT NOT NULL,
  calibrated_at TIMESTAMPTZ NOT NULL,
  valid_until TIMESTAMPTZ,
  issuer_name TEXT NOT NULL,
  document_hash CHAR(64),
  status TEXT NOT NULL CHECK (status IN ('CURRENT','EXPIRED','REVOKED','DEMO_ONLY')),
  is_simulated BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (sensor_id, calibration_code)
);

CREATE TABLE IF NOT EXISTS telemetry_readings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id UUID NOT NULL UNIQUE,
  sensor_id UUID NOT NULL REFERENCES sensors(id),
  key_id TEXT NOT NULL REFERENCES device_keys(key_id),
  site_id UUID NOT NULL REFERENCES sites(id),
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  boot_id TEXT NOT NULL,
  sequence_no BIGINT NOT NULL CHECK (sequence_no > 0),
  parameter TEXT NOT NULL CHECK (parameter IN ('pH','COD','TSS')),
  value_numeric NUMERIC(18,6) NOT NULL,
  value_wire TEXT NOT NULL,
  unit TEXT NOT NULL,
  measured_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  original_payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  signature_status TEXT NOT NULL CHECK (signature_status = 'VALID'),
  protocol_status TEXT NOT NULL,
  calibration_status TEXT NOT NULL DEFAULT 'UNKNOWN',
  witness_status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (sensor_id, boot_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_telemetry_station_time ON telemetry_readings(station_id, measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_sensor_time ON telemetry_readings(sensor_id, measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_site_time ON telemetry_readings(site_id, measured_at DESC);

CREATE TABLE IF NOT EXISTS operations_context_readings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id UUID NOT NULL UNIQUE,
  source_id TEXT NOT NULL,
  key_id TEXT NOT NULL REFERENCES operations_source_keys(key_id),
  site_id UUID NOT NULL REFERENCES sites(id),
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  sequence_no BIGINT NOT NULL,
  interval_start TIMESTAMPTZ NOT NULL,
  interval_end TIMESTAMPTZ NOT NULL,
  production_rate NUMERIC(18,6) NOT NULL,
  wastewater_flow NUMERIC(18,6) NOT NULL,
  treatment_dose NUMERIC(18,6) NOT NULL,
  energy_consumption NUMERIC(18,6) NOT NULL,
  operating_mode TEXT NOT NULL CHECK (operating_mode IN ('NORMAL','HIGH_LOAD','CLEANING','LOW_LOAD')),
  original_payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  verification_status TEXT NOT NULL CHECK (verification_status = 'VALID'),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (source_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_ops_station_interval ON operations_context_readings(station_id, interval_start DESC);

CREATE TABLE IF NOT EXISTS heartbeats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id UUID NOT NULL UNIQUE,
  sensor_id UUID NOT NULL REFERENCES sensors(id),
  key_id TEXT NOT NULL REFERENCES device_keys(key_id),
  boot_id TEXT NOT NULL,
  heartbeat_sequence BIGINT NOT NULL,
  sent_at TIMESTAMPTZ NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  signature_base64 TEXT NOT NULL,
  verification_status TEXT NOT NULL CHECK (verification_status = 'VALID'),
  UNIQUE (sensor_id, boot_id, heartbeat_sequence)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  event_sequence BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  entity_id TEXT,
  message_id UUID,
  event_payload JSONB NOT NULL,
  previous_hash CHAR(64),
  event_hash CHAR(64) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (station_id, event_sequence)
);

CREATE INDEX IF NOT EXISTS idx_audit_station_sequence ON audit_events(station_id, event_sequence);

CREATE TABLE IF NOT EXISTS audit_checkpoints_received (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  witness_id TEXT NOT NULL,
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  checkpoint_sequence BIGINT NOT NULL,
  last_witness_sequence BIGINT NOT NULL,
  chain_head_hash CHAR(64) NOT NULL,
  checkpoint_payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  witness_public_key_fingerprint CHAR(64) NOT NULL,
  verification_status TEXT NOT NULL CHECK (verification_status IN ('VALID','INVALID','PENDING')),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (witness_id, station_id, checkpoint_sequence)
);

CREATE TABLE IF NOT EXISTS security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id UUID REFERENCES sites(id),
  sensor_id UUID REFERENCES sensors(id),
  event_type TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  sanitized_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_events_site ON security_events(site_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS anomaly_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reading_id UUID NOT NULL REFERENCES telemetry_readings(id),
  model_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('CONSISTENT','SUSPICIOUS','NOT_EVALUATED','ERROR')),
  anomaly_type TEXT,
  actual_value NUMERIC(18,6),
  predicted_value NUMERIC(18,6),
  residual NUMERIC(18,6),
  threshold NUMERIC(18,6),
  reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
  evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS compliance_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  parameter TEXT NOT NULL,
  min_value NUMERIC(18,6),
  max_value NUMERIC(18,6),
  unit TEXT NOT NULL,
  version INTEGER NOT NULL,
  effective_from TIMESTAMPTZ NOT NULL,
  effective_to TIMESTAMPTZ,
  is_demo_value BOOLEAN NOT NULL DEFAULT TRUE,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (station_id, parameter, version),
  CHECK (min_value IS NOT NULL OR max_value IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS alert_investigations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  anomaly_result_id UUID REFERENCES anomaly_results(id),
  security_event_id UUID REFERENCES security_events(id),
  status TEXT NOT NULL CHECK (status IN ('OPEN','UNDER_REVIEW','RESOLVED','FALSE_POSITIVE','UNDETERMINED')),
  notes TEXT,
  created_by UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

