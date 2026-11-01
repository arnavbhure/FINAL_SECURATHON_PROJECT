-- Migration 008: Attack Simulation Lab evidence, demo identity marker, raw ML outputs
-- Demo-run evidence is stored separately from trusted telemetry and audit records.

-- 1. Marks sensors that exist only as dedicated Attack Lab demo identities.
ALTER TABLE sensors
  ADD COLUMN IF NOT EXISTS is_demo_identity BOOLEAN NOT NULL DEFAULT FALSE;

-- 2. Raw anomaly-model outputs exactly as returned by the ML service.
--    (predicted_value/residual/threshold remain as previously derived by the client adapter.)
ALTER TABLE anomaly_results
  ADD COLUMN IF NOT EXISTS anomaly_score NUMERIC(18,6),
  ADD COLUMN IF NOT EXISTS anomaly_threshold NUMERIC(18,6),
  ADD COLUMN IF NOT EXISTS is_anomaly BOOLEAN,
  ADD COLUMN IF NOT EXISTS detection_sources JSONB;

-- 3. Attack Lab run evidence (one row per scenario execution)
CREATE TABLE IF NOT EXISTS attack_lab_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scenario_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED', 'ABANDONED')),
  outcome TEXT CHECK (
    outcome IN ('PREVENTED', 'DETECTED', 'SUSPICIOUS', 'ACCEPTED', 'PENDING', 'INCONCLUSIVE', 'SERVICE_UNAVAILABLE')
  ),
  classification TEXT,
  summary TEXT,
  expectation_met BOOLEAN,
  actor_user_id UUID REFERENCES users(id),
  actor_label TEXT NOT NULL,
  actor_source TEXT NOT NULL CHECK (actor_source IN ('UI', 'CLI', 'TEST')),
  site_code TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  steps JSONB NOT NULL DEFAULT '[]'::jsonb,
  primary_outcome JSONB,
  witness_outcome JSONB,
  ml_result JSONB,
  alert_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  security_event_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
  verification_evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  error TEXT
);

-- At most one scenario may execute at a time (UI, CLI and tests share this guard).
CREATE UNIQUE INDEX IF NOT EXISTS uq_attack_lab_runs_single_running
  ON attack_lab_runs ((status)) WHERE status = 'RUNNING';
CREATE INDEX IF NOT EXISTS idx_attack_lab_runs_started ON attack_lab_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_lab_runs_scenario ON attack_lab_runs (scenario_id, started_at DESC);

-- 4. Lookup support for security events by request ID (evidence linking).
CREATE INDEX IF NOT EXISTS idx_security_events_request_id
  ON security_events ((sanitized_metadata->>'requestId'));
