-- Migration 006: ML Assessment Results Extension and Job Queue

-- 1. Extend anomaly_results table with site reference, context reference, and severity
ALTER TABLE anomaly_results
  ADD COLUMN IF NOT EXISTS site_id UUID REFERENCES sites(id),
  ADD COLUMN IF NOT EXISTS context_id UUID REFERENCES operations_context_readings(id),
  ADD COLUMN IF NOT EXISTS severity TEXT CHECK (severity IN ('NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') OR severity IS NULL),
  ADD COLUMN IF NOT EXISTS processing_status TEXT NOT NULL DEFAULT 'COMPLETED';

-- Ensure 1:1 reading to anomaly_result
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'uq_anomaly_results_reading'
  ) THEN
    ALTER TABLE anomaly_results ADD CONSTRAINT uq_anomaly_results_reading UNIQUE (reading_id);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_anomaly_results_site ON anomaly_results(site_id, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_reading ON anomaly_results(reading_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_status ON anomaly_results(status);

-- 2. Create ml_assessment_jobs table for asynchronous resilient processing
CREATE TABLE IF NOT EXISTS ml_assessment_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reading_id UUID NOT NULL REFERENCES telemetry_readings(id) UNIQUE,
  site_id UUID NOT NULL REFERENCES sites(id),
  sensor_id UUID NOT NULL REFERENCES sensors(id),
  status TEXT NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'INSUFFICIENT_CONTEXT')),
  attempts INT NOT NULL DEFAULT 0,
  max_attempts INT NOT NULL DEFAULT 3,
  last_error TEXT,
  next_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_at TIMESTAMPTZ,
  locked_by TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ml_jobs_queue ON ml_assessment_jobs(status, next_run_at)
  WHERE status IN ('PENDING', 'PROCESSING');
CREATE INDEX IF NOT EXISTS idx_ml_jobs_site ON ml_assessment_jobs(site_id, created_at DESC);

