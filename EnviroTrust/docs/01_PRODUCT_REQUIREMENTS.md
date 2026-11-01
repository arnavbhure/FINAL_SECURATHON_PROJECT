# 01 — Product Requirements Document

## 1. Product identity

**Name:** EnviroTrust  
**Tagline:** Verify the source. Preserve the history. Question suspicious measurements.  
**Domain:** Water and Waste Management  
**Subdomain:** Industrial effluent monitoring data integrity  
**Product category:** Security and monitoring verification platform  
**Prototype type:** Software-only simulated environment

## 2. Problem statement

Industrial effluent monitoring systems collect and transmit measurement records. A dashboard that displays numbers alone does not provide sufficient independent evidence about the origin, integrity, availability or plausibility of those records.

A monitoring record can be problematic for different reasons:

- It may have been altered after the sensor signed it.
- It may be submitted by an unknown, unapproved or revoked device key.
- An old valid record may be replayed.
- Records may be deleted, reordered or presented differently to different parties.
- A device may stop sending measurements or heartbeats.
- A sensor may continue signing readings that are stuck, drifting or inconsistent with operational context.
- A valid reading may exceed a configured environmental threshold.

These are not one single problem. EnviroTrust separates authenticity, audit integrity, availability, measurement behaviour and compliance status.

## 3. Product objective

Build a demonstrable platform that:

1. Authenticates simulated sensor telemetry through Ed25519 digital signatures.
2. Detects modification of signed payloads and rejects replayed submissions.
3. Preserves an append-only primary event chain.
4. Sends the same signed sensor envelope directly to an independent witness service, which verifies and stores its own copy.
5. Uses separate witness signing keys to issue periodic signed checkpoints.
6. Monitors signed sensor heartbeats and reports missing communication.
7. Uses separate signed industrial operating-context data to estimate expected outlet COD and detect large, unexplained deviations.
8. Detects sensor flatlining and sudden changes through deterministic statistical rules.
9. Provides role-specific dashboards for administrators, factory operators and regulators/auditors.
10. Demonstrates attack scenarios live without claiming that simulations prove real-world fraud.

## 4. Target users

### 4.1 Platform administrator

A platform-level operator who provisions sites, stations, sensors, device public keys, users and monitoring configuration. The administrator cannot edit accepted telemetry through normal application workflows.

### 4.2 Factory operator

A facility-scoped user who views their own site's readings, device health, process alerts, anomaly alerts and reports. In demo mode, authorized operators may start/stop simulations and trigger approved attack scenarios.

### 4.3 Regulator/auditor

A read-only oversight user who can view authorized sites, inspect signed readings, compare primary and witness histories, verify signed checkpoints, see missing heartbeats and review anomaly/compliance alerts. The auditor cannot alter original readings or audit events.

### 4.4 Sensor machine identity

A registered simulated device, not a human dashboard account. It sends signed telemetry and heartbeats to designated endpoints. It has no dashboard session and no access to other sensor data.

### 4.5 Independent witness service

A separately operated software service representing a hypothetical independent university/NGO/audit witness. In the prototype it is simulated. It receives signed data directly from sensor simulators, independently verifies it and maintains its own records.

## 5. Product boundaries

EnviroTrust is not:

- A replacement for CPCB/MPCB OCEMS or any official portal.
- A real-time certified pollution measurement instrument.
- A substitute for laboratory testing or calibration.
- A legal determination of environmental compliance.
- A device-hardware security implementation.
- A real NGO/university/regulator integration in the hackathon prototype.
- A blockchain platform.

## 6. Core user journeys

### Journey A — Admin provisions site and devices

1. Admin signs in.
2. Creates one demo industrial site.
3. Creates one ETP outlet monitoring station.
4. Runs a provisioning utility to generate sensor and operations key pairs.
5. Reviews public-key fingerprints and approves the keys.
6. Public keys are registered in both primary and witness registries.
7. Private keys remain in local simulator key storage.

### Journey B — Sensor sends a reading

1. Sensor simulator creates a telemetry payload.
2. It canonicalizes the payload using RFC 8785 JCS.
3. It signs the canonical bytes using its Ed25519 private key.
4. It sends the same envelope over HTTPS to the primary API and witness API.
5. Primary independently verifies signature, key mapping, sequence and freshness.
6. Witness independently verifies signature, key mapping and sequence.
7. Each service stores its own copy and appends to its own event chain.
8. Witness signs a periodic checkpoint.
9. Primary joins accepted COD telemetry with verified operational context and calls the ML service.
10. Dashboard updates status indicators and alerts.

### Journey C — Auditor verifies a reading/history

1. Auditor opens the site and selects a time range.
2. Sees the original signed payload, signature status, key fingerprint and server receipt time.
3. Sees primary event-chain status.
4. Sees witness receipt status and signed checkpoint.
5. Runs a primary-versus-witness reconciliation.
6. Sees matching, missing or mismatched records.
7. Downloads a verification report containing hashes, status and limitations.

### Journey D — Operator investigates anomaly

1. Operator opens anomaly investigation.
2. Sees actual COD, model-predicted COD, residual and threshold.
3. Sees the verified production/flow/treatment context used by the model.
4. Sees reasons for the alert.
5. Records an investigation status and notes.
6. Original signed telemetry remains unchanged.

## 7. Functional requirements

### Identity and access

- FR-AUTH-01: Users can sign in and sign out.
- FR-AUTH-02: Server-side authorization enforces `PLATFORM_ADMIN`, `FACTORY_OPERATOR` and `REGULATOR_AUDITOR`.
- FR-AUTH-03: Factory operators can access only assigned sites.
- FR-AUTH-04: Regulator/auditor accounts have read-only access to assigned sites.
- FR-AUTH-05: Sensor identities authenticate telemetry through registered cryptographic keys, not dashboard credentials.

### Site and device registry

- FR-REG-01: Admin can create one or more sites and monitoring stations.
- FR-REG-02: Admin can register a sensor with parameter, unit, site and station mapping.
- FR-REG-03: Admin can approve a sensor public key after reviewing its fingerprint.
- FR-REG-04: Admin can revoke a key; new submissions using a revoked key are rejected.
- FR-REG-05: Key history is retained.

### Telemetry

- FR-TEL-01: Each simulator emits a schema-valid signed reading.
- FR-TEL-02: Signed payload includes sensor identity, key ID, site/station, parameter, decimal-string value, unit, timestamp, sequence and boot ID.
- FR-TEL-03: Primary verifies Ed25519 signature against a pre-enrolled public key.
- FR-TEL-04: Primary checks identity mapping and replay/freshness rules.
- FR-TEL-05: Accepted readings are immutable in normal application workflows.
- FR-TEL-06: Environmental exceedances are stored and flagged, not rejected as cryptographically invalid.

### Witness and audit

- FR-AUD-01: Sensor sends the same envelope directly to primary and witness.
- FR-AUD-02: Witness independently verifies signature and device mapping.
- FR-AUD-03: Primary and witness store independent event histories.
- FR-AUD-04: Each service computes a hash chain for its own events.
- FR-AUD-05: Witness signs checkpoints at configurable event intervals.
- FR-AUD-06: Auditor can compare primary and witness records by message ID and payload hash.
- FR-AUD-07: A missing or mismatched record is visibly reported.

### Availability

- FR-AVL-01: Each sensor sends a signed heartbeat at a configurable interval.
- FR-AVL-02: Backend tracks last accepted heartbeat.
- FR-AVL-03: After the configured number of missed intervals, sensor status changes to `OFFLINE`.
- FR-AVL-04: Dashboard describes this as communication loss, not proven deliberate shutdown.

### Operations context and ML

- FR-ML-01: A separate operations simulator generates production, wastewater flow, treatment dosage, energy and operating mode.
- FR-ML-02: Operations context is signed with a separate source key and verified by primary.
- FR-ML-03: ML service predicts expected outlet COD from the documented context features.
- FR-ML-04: ML result includes predicted COD, residual, validation-derived threshold, model version and explanation.
- FR-ML-05: Missing or stale context produces `NOT_EVALUATED`.
- FR-ML-06: Flatline and sudden-change rules produce separate sensor-behaviour alerts.
- FR-ML-07: Anomaly output never changes original telemetry.

### Compliance

- FR-COMP-01: Parameter thresholds are configurable per station and versioned.
- FR-COMP-02: Compliance threshold exceedance is separate from signature validity and ML anomaly.
- FR-COMP-03: Demo limits are labelled simulated and are not represented as universal legal limits.

### Demo/attack simulation

- FR-DEMO-01: Demo controls can trigger modified-in-transit payload, database tampering fixture, replay, flatline, suspicious COD context mismatch and simulator shutdown.
- FR-DEMO-02: Demo endpoints are disabled outside demo/development mode.
- FR-DEMO-03: Attacks are restricted to synthetic demo records and cannot be used to modify production records.

## 8. Non-functional requirements

- NFR-01: Security checks run server-side.
- NFR-02: All networked services validate input and limit request size.
- NFR-03: Database writes use transactions and parameterized queries.
- NFR-04: Private keys and secrets are never committed or sent to the browser.
- NFR-05: UI status labels are precise and explain their meaning.
- NFR-06: Every security alert has an event/time/source reference.
- NFR-07: The app remains usable on a laptop during a live demo.
- NFR-08: The system must show demo/simulated-data labels persistently.
- NFR-09: The ML service must return within a bounded timeout; ingestion should not be lost if ML is temporarily unavailable.
- NFR-10: Services log errors without logging private keys, passwords or secret tokens.

## 9. Success metrics for the demo

- Valid signed reading accepted by both primary and witness.
- Modified signed payload rejected by signature verification.
- Duplicate sequence rejected as replay.
- Primary record modification detected by witness reconciliation/checkpoint.
- Sensor process shutdown results in missing-heartbeat alert within configured timeout.
- Validly signed COD reading can trigger process-context anomaly.
- Auditor can inspect the reason and cryptographic evidence behind each status.
