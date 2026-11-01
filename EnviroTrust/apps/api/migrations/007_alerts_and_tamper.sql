-- Migration 007: Alerts and Tamper Events
-- EnviroTrust Alert & Incident Management System

CREATE TABLE IF NOT EXISTS tamper_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL UNIQUE,
  sensor_id UUID NOT NULL REFERENCES sensors(id),
  site_id UUID NOT NULL REFERENCES sites(id),
  station_id UUID NOT NULL REFERENCES monitoring_stations(id),
  key_id TEXT NOT NULL REFERENCES device_keys(key_id),
  event_type TEXT NOT NULL CHECK (event_type IN ('ENCLOSURE_OPENED', 'PHYSICAL_INTERFERENCE', 'DEVICE_MOVEMENT')),
  event_timestamp TIMESTAMPTZ NOT NULL,
  tamper_source TEXT NOT NULL,
  sequence_no BIGINT NOT NULL,
  original_payload JSONB NOT NULL,
  signature_base64 TEXT NOT NULL,
  payload_hash CHAR(64) NOT NULL,
  signature_status TEXT NOT NULL CHECK (signature_status = 'VALID'),
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (sensor_id, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_tamper_sensor_time ON tamper_events(sensor_id, event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tamper_site_time ON tamper_events(site_id, event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tamper_event_id ON tamper_events(event_id);

CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  site_id UUID NOT NULL REFERENCES sites(id),
  sensor_id UUID REFERENCES sensors(id),
  station_id UUID REFERENCES monitoring_stations(id),
  alert_type TEXT NOT NULL CHECK (alert_type IN ('PHYSICAL_TAMPER', 'SENSOR_STALE', 'SENSOR_OFFLINE', 'SENSOR_RECOVERED', 'SECURITY_EVENT')),
  severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'WARNING', 'INFO')),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  source_event_id UUID,
  detection_source TEXT NOT NULL DEFAULT 'SYSTEM',
  status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
  recommended_action TEXT NOT NULL,
  deduplication_key TEXT UNIQUE,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ,
  acknowledged_by UUID REFERENCES users(id),
  resolved_at TIMESTAMPTZ,
  resolved_by UUID REFERENCES users(id),
  resolution_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_site_status ON alerts(site_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_sensor_type_status ON alerts(sensor_id, alert_type, status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

