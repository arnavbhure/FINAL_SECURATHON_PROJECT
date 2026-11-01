# 07 — Database Model and API Contracts

## 1. Database principles

- PostgreSQL is the primary application database.
- Witness must use separate storage and separate credentials.
- Use UUID primary keys where appropriate.
- Use `JSONB` for the original validated payload, but also store indexed identity/sequence columns.
- Store signature as Base64 text or binary bytes; choose one consistently.
- Store payload/event hashes as 64-character lowercase SHA-256 hex.
- Store timestamps in UTC (`timestamptz`).
- Use decimal/numeric for environmental values when stored numerically; signed wire payload value remains a decimal string.
- Add unique constraints for message IDs and sensor boot/sequence pairs.
- Accepted telemetry and audit events are append-only in application logic.
- Use transactions for replay check + telemetry insert + audit append.

## 2. Primary entities

### `users`

Human dashboard accounts: id, name, email, password_hash, status, created_at.

### `sites`

Industrial site metadata: id, site_code, name, industry_type, demo_label, status, created_at.

### `site_memberships`

Connect user to site and role. Platform admin is platform-level; factory operator and auditor are site-scoped.

### `monitoring_stations`

id, site_id, station_code, name, station_type (e.g. `ETP_OUTLET`), status.

### `sensors`

id, sensor_code, station_id, parameter (`pH`, `COD`, `TSS`), unit, status, expected_interval_seconds, created_at.

### `device_keys`

id, key_id, sensor_id, algorithm (`Ed25519`), public_key_pem, fingerprint_sha256, status, valid_from, valid_to, revoked_at, created_at.

### `operations_source_keys`

id, key_id, source_id (`OPS-001`), site_id, station_id, algorithm, public_key_pem, fingerprint_sha256, status, validity and revocation timestamps. It is separate from sensor keys because the operations source is a different signing identity.

### `calibration_records`

id, sensor_id, calibration_code, calibrated_at, valid_until, issuer_name (demo), document_hash, status. Do not claim actual calibration if records are synthetic.

### `telemetry_readings`

id, message_id, site_id, station_id, sensor_id, key_id, boot_id, sequence_no, parameter, value_numeric, unit, measured_at, received_at, original_payload JSONB, signature_base64, payload_hash, signature_status, protocol_status, calibration_status, witness_status, created_at. Do not update original_payload, signature or payload_hash after insertion.

Unique: message_id; `(sensor_id, boot_id, sequence_no)`.

### `operations_context_readings`

id, message_id, site_id, station_id, source_id, key_id, sequence_no, interval_start, interval_end, production_rate, wastewater_flow, treatment_dose, energy_consumption, operating_mode, original_payload JSONB, signature_base64, payload_hash, verification_status, received_at. Unique message ID and source/sequence.

### `heartbeats`

id, message_id, sensor_id, key_id, boot_id, heartbeat_sequence, sent_at, received_at, signature_base64, verification_status. Unique message ID and sensor/boot/heartbeat sequence.

### `audit_events`

id, station_id, event_sequence, event_type, entity_id, message_id nullable, event_payload JSONB, previous_hash, event_hash, created_at. Unique `(station_id, event_sequence)`.

### `security_events`

id, site_id, sensor_id nullable, event_type, reason_code, sanitized_metadata JSONB, occurred_at, created_at. Security events are not trusted telemetry.

### `anomaly_results`

id, reading_id, model_version, status, anomaly_type, actual_value, predicted_value, residual, threshold, reasons JSONB, evaluated_at.

### `compliance_profiles`

id, station_id, parameter, min_value nullable, max_value nullable, unit, version, effective_from, effective_to nullable, is_demo_value, created_by.

### `audit_checkpoints_received`

id, witness_id, station_id, checkpoint_sequence, last_witness_sequence, chain_head_hash, checkpoint_payload JSONB, signature_base64, witness public-key fingerprint, received_at, verification_status.

## 3. Witness entities (separate database/storage)

### `witness_sensor_keys`

key_id, sensor_id, site_id, station_id, parameter, public_key_pem, fingerprint_sha256, status, provisioned_at.

### `witness_events`

id, witness_sequence, message_id, site_id, station_id, sensor_id, key_id, sensor_boot_id, sensor_sequence, payload JSONB, signature_base64, payload_hash, witness_received_at, previous_hash, event_hash. Unique message_id and `(sensor_id, sensor_boot_id, sensor_sequence)`.

### `witness_checkpoints`

id, witness_id, station_id, checkpoint_sequence, last_witness_sequence, chain_head_hash, previous_checkpoint_hash, created_at, canonical_payload, signature_base64, checkpoint_hash.

### `witness_heartbeats`

id, message_id, sensor_id, boot_id, heartbeat_sequence, sent_at, received_at, signature_base64. Unique message and sequence identity.

The witness must retain its own copy; do not simply query primary tables when verifying history.

## 4. API conventions

- Prefix primary routes with `/api/v1`.
- Prefix witness routes with `/witness/v1`.
- Return JSON.
- Use stable `code` values in errors.
- Use `requestId` for traceability.
- Do not return private keys, raw secrets or database details.
- All user routes require authentication and RBAC.
- Sensor routes require cryptographic verification; they do not use browser user sessions.
- Demo routes require `DEMO_MODE=true` and admin/operator role.

## 5. Primary API routes

### Authentication

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/me`

### Administration

- `POST /api/v1/sites`
- `GET /api/v1/sites`
- `POST /api/v1/sites/:siteId/stations`
- `GET /api/v1/sites/:siteId/stations`
- `POST /api/v1/sensors`
- `GET /api/v1/sensors`
- `POST /api/v1/sensors/:sensorId/keys`
- `POST /api/v1/keys/:keyId/revoke`

### Telemetry machine endpoint

- `POST /api/v1/ingestion/readings`
- `POST /api/v1/ingestion/heartbeats`
- `POST /api/v1/ingestion/operations-context`
- `POST /api/v1/ingestion/challenges` and `POST /api/v1/ingestion/challenges/:challengeId/response` (P1 optional liveness challenge only; never physical calibration)
- `POST /api/v1/ingestion/challenges` and `POST /api/v1/ingestion/challenges/:challengeId/response` (P1 optional liveness challenge only; never physical calibration)

### Monitoring

- `GET /api/v1/sites/:siteId/overview`
- `GET /api/v1/sites/:siteId/readings`
- `GET /api/v1/sensors/:sensorId/status`
- `GET /api/v1/alerts`
- `GET /api/v1/readings/:readingId/verification`

### Audit

- `GET /api/v1/audit/events`
- `POST /api/v1/audit/reconcile`
- `GET /api/v1/audit/checkpoints`
- `GET /api/v1/audit/reports/:reportId` (if report export is implemented)

### Investigation/configuration

- `POST /api/v1/alerts/:alertId/investigations`
- `PATCH /api/v1/alerts/:alertId/status`
- `GET /api/v1/compliance-profiles`
- `POST /api/v1/compliance-profiles` (admin only; versioned)

### Demo-only

- `POST /api/v1/demo/simulator/start`
- `POST /api/v1/demo/simulator/stop`
- `POST /api/v1/demo/scenarios`
- `GET /api/v1/demo/status`

## 6. Witness API routes

- `POST /witness/v1/ingestion/readings`
- `POST /witness/v1/ingestion/heartbeats`
- `POST /witness/v1/ingestion/operations-context` (only if operations context is also retained by witness; P1, not required for P0)
- `POST /witness/v1/ingestion/operations-context` (only if operations context is also retained by witness; P1, not required for P0)
- `GET /witness/v1/checkpoints/latest?stationId=...`
- `GET /witness/v1/events?stationId=...&fromSequence=...&toSequence=...`
- `POST /witness/v1/verify/reconcile` (internal/auditor-safe read-only operation)
- `GET /witness/v1/health`

Sensor ingestion is authenticated by its enrolled signature. Administrative witness routes must be protected separately. The witness signing private key is never exposed.

## 7. ML API

- `POST /ml/v1/analyze/cod` — request body follows `contracts/ml-request.schema.json`; response follows `contracts/ml-result.schema.json`.
- `GET /ml/v1/health` — returns service readiness and model version; do not expose secrets.

Only primary backend should call ML. It must send `Authorization: Bearer <ML_SERVICE_TOKEN>` when service authentication is enabled. The request must explicitly state `contextVerified: true` only after backend has verified the operations-source signature, key mapping, time validity and interval alignment. Do not trust a public caller/browser to set this flag. The ML service must validate the token and request schema. See `06_ML_SPECIFICATION.md` and `ENVIRONMENT_SETUP.md`.

## 8. Error response format

```json
{
  "success": false,
  "code": "INVALID_SIGNATURE",
  "message": "The submitted telemetry signature could not be verified.",
  "requestId": "uuid"
}
```

Do not reveal whether a secret/private key exists. More detailed sanitized diagnostic reason can be stored internally.

## 9. Example telemetry response

Accepted primary ingestion response:

```json
{
  "success": true,
  "messageId": "UUID",
  "signatureStatus": "VALID",
  "protocolStatus": "FRESH",
  "primaryAuditSequence": 42,
  "witnessStatus": "PENDING",
  "receivedAt": "UTC timestamp"
}
```

The witness status is `RECEIVED` only after a successful witness acknowledgement. Never report it as received merely because primary attempted a request.

Example verification response:

```json
{
  "messageId": "UUID",
  "signatureStatus": "VALID",
  "keyId": "COD-KEY-V1",
  "payloadHash": "64-char-sha256-hex",
  "sequenceStatus": "FRESH",
  "witnessStatus": "MATCHED",
  "mlStatus": "SUSPICIOUS",
  "complianceStatus": "NOT_EVALUATED"
}
```

The values above are examples, not hardcoded statuses.

## 10. Authentication and session implementation

For the prototype, use Argon2id password hashes if the Node package can be installed reliably. If installation blocks the time-box, use a maintained bcrypt implementation rather than custom hashing. Never store plaintext passwords. Use a short-lived access session/token in an HttpOnly cookie where the deployment model supports it; do not store long-lived bearer tokens in localStorage. Protect cookie-authenticated state-changing routes against CSRF, configure exact CORS origins, and enforce roles/site scope in middleware. Seed demo accounts through a script, not public registration.

## 11. Idempotency and retry

- Sensor `messageId` is generated once before signing.
- Retry uses exactly the same payload, message ID, signature, boot ID and sequence.
- Primary and witness return an idempotent duplicate response for a previously accepted identical message.
- Same `messageId` with different payload/signature is a security conflict.
- Do not append the same event twice.

## 12. SQL files

`database/primary-schema.sql` and `database/witness-schema.sql` provide reference DDL. If using an ORM, create migrations with equivalent constraints and indexes.
