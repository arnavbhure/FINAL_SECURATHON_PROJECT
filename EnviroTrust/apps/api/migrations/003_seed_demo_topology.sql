-- Migration 003: Seed Demo Topology
-- Fixed identifiers per docs/13_DECISIONS_AND_OPEN_ITEMS.md:
-- Site: PLANT-001
-- Station: ETP-OUTLET-001
-- Sensors: PH-OUT-001, COD-OUT-001, TSS-OUT-001
-- Operations Source: OPS-001

DO $$
DECLARE
  v_site_id UUID;
  v_station_id UUID;
  v_ph_sensor_id UUID;
  v_cod_sensor_id UUID;
  v_tss_sensor_id UUID;
  v_genesis_hash CHAR(64) := '0000000000000000000000000000000000000000000000000000000000000000';
BEGIN
  -- 1. Insert or get site PLANT-001
  INSERT INTO sites (site_code, name, industry_type, is_demo, status)
  VALUES ('PLANT-001', 'Demo Industrial Effluent Treatment Facility', 'Textile & Chemical Effluent', TRUE, 'ACTIVE')
  ON CONFLICT (site_code) DO UPDATE
    SET name = EXCLUDED.name,
        industry_type = EXCLUDED.industry_type,
        status = EXCLUDED.status
  RETURNING id INTO v_site_id;

  -- 2. Insert or get station ETP-OUTLET-001
  INSERT INTO monitoring_stations (site_id, station_code, name, station_type, status)
  VALUES (v_site_id, 'ETP-OUTLET-001', 'Effluent Treatment Plant Final Discharge Outlet', 'ETP_OUTLET', 'ACTIVE')
  ON CONFLICT (site_id, station_code) DO UPDATE
    SET name = EXCLUDED.name,
        status = EXCLUDED.status
  RETURNING id INTO v_station_id;

  -- 3. Insert or get sensors
  INSERT INTO sensors (sensor_code, station_id, parameter, unit, expected_interval_seconds, status)
  VALUES ('PH-OUT-001', v_station_id, 'pH', 'pH', 7, 'ACTIVE')
  ON CONFLICT (sensor_code) DO UPDATE
    SET station_id = EXCLUDED.station_id,
        unit = EXCLUDED.unit,
        status = EXCLUDED.status
  RETURNING id INTO v_ph_sensor_id;

  INSERT INTO sensors (sensor_code, station_id, parameter, unit, expected_interval_seconds, status)
  VALUES ('COD-OUT-001', v_station_id, 'COD', 'mg/L', 7, 'ACTIVE')
  ON CONFLICT (sensor_code) DO UPDATE
    SET station_id = EXCLUDED.station_id,
        unit = EXCLUDED.unit,
        status = EXCLUDED.status
  RETURNING id INTO v_cod_sensor_id;

  INSERT INTO sensors (sensor_code, station_id, parameter, unit, expected_interval_seconds, status)
  VALUES ('TSS-OUT-001', v_station_id, 'TSS', 'mg/L', 7, 'ACTIVE')
  ON CONFLICT (sensor_code) DO UPDATE
    SET station_id = EXCLUDED.station_id,
        unit = EXCLUDED.unit,
        status = EXCLUDED.status
  RETURNING id INTO v_tss_sensor_id;

  -- 4. Initialize station audit cursor if not present
  INSERT INTO station_audit_cursors (station_id, last_event_sequence, chain_head_hash)
  VALUES (v_station_id, 0, v_genesis_hash)
  ON CONFLICT (station_id) DO NOTHING;

  -- 5. Seed baseline compliance profiles (clearly marked as demo)
  INSERT INTO compliance_profiles (station_id, parameter, min_value, max_value, unit, version, effective_from, is_demo_value)
  VALUES
    (v_station_id, 'pH', 6.5, 8.5, 'pH', 1, now(), TRUE),
    (v_station_id, 'COD', NULL, 250.0, 'mg/L', 1, now(), TRUE),
    (v_station_id, 'TSS', NULL, 100.0, 'mg/L', 1, now(), TRUE)
  ON CONFLICT (station_id, parameter, version) DO NOTHING;

END
$$;

