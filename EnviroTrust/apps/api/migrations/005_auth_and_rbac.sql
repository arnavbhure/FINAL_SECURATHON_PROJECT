-- Migration 005: Human Authentication, RBAC, Sessions & State Transitions
-- Implements tables and constraints required by Prompt 6.

-- 1. Upgrade users table to support role-based access control
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT;

-- Populate default role for existing users
UPDATE users SET role = 'PLATFORM_ADMIN' WHERE global_role = 'PLATFORM_ADMIN' AND role IS NULL;
UPDATE users SET role = 'FACTORY_OPERATOR' WHERE role IS NULL;

-- Enforce valid roles on users
ALTER TABLE users ALTER COLUMN role SET NOT NULL;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('PLATFORM_ADMIN', 'FACTORY_OPERATOR', 'REGULATOR_AUDITOR'));

ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

-- Normalized case-insensitive unique email index
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_normalized_email ON users (LOWER(email));

-- 2. User Site Memberships table
CREATE TABLE IF NOT EXISTS user_site_memberships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, site_id)
);

CREATE INDEX IF NOT EXISTS idx_user_site_memberships_user ON user_site_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_user_site_memberships_site ON user_site_memberships(site_id);

-- Backfill from legacy site_memberships table if present
INSERT INTO user_site_memberships (user_id, site_id)
SELECT DISTINCT user_id, site_id
FROM site_memberships
ON CONFLICT (user_id, site_id) DO NOTHING;

-- 3. Authentication Sessions table (storing SHA-256 hash of refresh token, never raw token)
CREATE TABLE IF NOT EXISTS authentication_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON authentication_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON authentication_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON authentication_sessions(expires_at);

-- 4. Sensor State Transitions table (persistent audit of OFFLINE -> ONLINE recovery, etc.)
CREATE TABLE IF NOT EXISTS sensor_state_transitions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sensor_id UUID NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
  from_status TEXT NOT NULL,
  to_status TEXT NOT NULL,
  reason TEXT NOT NULL,
  heartbeat_id UUID REFERENCES heartbeats(id) ON DELETE SET NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_sensor_state_transitions_sensor ON sensor_state_transitions(sensor_id, occurred_at DESC);

-- 5. Authentication and Administrative Audit Events table
CREATE TABLE IF NOT EXISTS auth_audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  actor_email TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_actor ON auth_audit_events(actor_email, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_audit_action ON auth_audit_events(action, occurred_at DESC);

-- 6. Provision second site PLANT-002 for multi-site isolation testing
INSERT INTO sites (site_code, name, industry_type, is_demo, status)
VALUES ('PLANT-002', 'EnviroTrust Secondary Plant 02', 'TEXTILE_DYEING', true, 'ACTIVE')
ON CONFLICT (site_code) DO NOTHING;

INSERT INTO monitoring_stations (site_id, station_code, name, station_type, status)
SELECT s.id, 'STATION-002', 'Secondary ETP Outlet', 'ETP_OUTLET', 'ACTIVE'
FROM sites s WHERE s.site_code = 'PLANT-002'
ON CONFLICT (site_id, station_code) DO NOTHING;

INSERT INTO sensors (sensor_code, station_id, parameter, unit, expected_interval_seconds, status)
SELECT 'PH-OUT-002', st.id, 'pH', 'pH', 10, 'ACTIVE'
FROM monitoring_stations st
JOIN sites s ON s.id = st.site_id
WHERE s.site_code = 'PLANT-002' AND st.station_code = 'STATION-002'
ON CONFLICT (sensor_code) DO NOTHING;

INSERT INTO sensors (sensor_code, station_id, parameter, unit, expected_interval_seconds, status)
SELECT 'COD-OUT-002', st.id, 'COD', 'mg/L', 10, 'ACTIVE'
FROM monitoring_stations st
JOIN sites s ON s.id = st.site_id
WHERE s.site_code = 'PLANT-002' AND st.station_code = 'STATION-002'
ON CONFLICT (sensor_code) DO NOTHING;
