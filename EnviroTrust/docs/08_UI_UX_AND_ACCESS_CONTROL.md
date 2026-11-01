# 08 — UI, User Roles and Interaction Specification

## 1. Design objective

The UI must communicate trust and investigation status, not look like a generic analytics dashboard. Prioritise information hierarchy, readable time-series charts, clear evidence trails and precise status labels.

Use a restrained industrial/monitoring visual language:

- Deep navy/charcoal for primary structure.
- Off-white or neutral surface for data-heavy pages.
- Teal/green for verified states.
- Amber for warning/uncertain states.
- Red for integrity failure or critical alerts.
- Muted grey for unavailable/neutral metadata.

Use colour plus text/icon; never rely on colour alone. Ensure keyboard access, visible focus, adequate contrast, responsive layout and semantic labels. Avoid excessive cards, gradients, glow, glassmorphism, decorative charts and unnecessary animation.

Every page must show a visible `SIMULATED DATA — HACKATHON PROTOTYPE` label.

## 2. Navigation

Common shell:

- Site selector (only sites the user is allowed to access).
- Monitoring Overview.
- Sensors & Keys.
- Security Events.
- Audit & Witness.
- Anomaly Investigation.
- Reports (if implemented).
- User/profile menu.

Show only permitted navigation items, but enforce all access in the backend too.

## 3. Login

- Email and password.
- Clear invalid-credential message without revealing which field is wrong.
- No public self-registration in MVP; seed demo users or let platform admin create users.
- Do not show sensor key provisioning on login page.

## 4. Monitoring Overview

Must show:

- Selected site and monitoring station.
- Latest pH/COD/TSS values with units and timestamps.
- Small history charts.
- Sensor availability: online/stale/offline.
- Separate cryptographic status summary.
- Separate witness status summary.
- Separate environmental exceedance alerts.
- Separate ML anomaly alerts.
- Data gap indicator.

Do not combine all statuses into a single “security score.”

## 5. Sensor Registry

Columns:

- Sensor ID.
- Parameter/unit.
- Site/station.
- Current status.
- Active key ID.
- Public-key fingerprint (short display + copy full fingerprint).
- Key status.
- Last heartbeat.
- Calibration record status (if seeded).

Actions:

- Admin: approve/enroll key, revoke key, inspect history.
- Operator: read-only sensor status.
- Auditor: read-only sensor/key fingerprint and verification history.

Never display private key material.

## 6. Security Center

Show security events in a filterable table:

- Invalid signature.
- Unknown key.
- Sensor/key mapping mismatch.
- Duplicate/replayed sequence.
- Timestamp failure.
- Witness lag/mismatch.
- Missing heartbeat.

Each event should have time, site, sensor, event type, severity, reason and a link to its evidence. Do not label every event as fraud.

## 7. Audit & Witness Explorer

Show:

- Primary event sequence and chain status.
- Witness event sequence and chain status.
- Latest signed checkpoint sequence.
- Witness public-key fingerprint.
- Reconciliation result.
- Missing-from-primary / missing-from-witness / payload mismatch counts.
- Event details including payload hash, previous hash and current hash.
- A “Verify range” action for an auditor/admin.

Clearly label the witness as simulated. Use wording such as `Independent witness receipt confirmed`, not `NGO certified`, unless a real organisation is connected and there is documented approval.

## 8. Anomaly Investigation

For each alert show:

- Sensor/parameter/site/time.
- Actual COD.
- Model-predicted COD.
- Absolute residual.
- Validation-derived alert threshold.
- Model version.
- Verified operating-context features.
- Reasons.
- Related signature and witness statuses.
- Investigation status and notes.

Investigation states: `OPEN`, `UNDER_REVIEW`, `RESOLVED`, `FALSE_POSITIVE`, `UNDETERMINED`. A user's resolution is an appended audit event; it does not delete the alert.

## 9. Attack Simulator

Only show in demo mode and to authorized admin/operator roles.

Scenarios:

1. Modify a signed payload after signature.
2. Replay a previously accepted envelope.
3. Tamper with a primary database audit record (test fixture only).
4. Stop one simulator to cause heartbeat loss.
5. Generate validly signed flatline readings.
6. Generate validly signed context-inconsistent COD.

Each scenario must explain what it changes and which layer should detect it. Attack controls must not operate on non-demo/real data.

## 10. Role matrix

| Capability | Platform admin | Factory operator | Regulator/auditor |
|---|---:|---:|---:|
| View assigned site data | Yes | Yes | Yes |
| View all sites | Yes | No | Only assigned/authorized sites |
| Create site/station | Yes | No | No |
| Register/approve sensor key | Yes | No | Read-only |
| Revoke sensor key | Yes | No | No |
| View telemetry | Yes | Own site | Authorized site |
| Edit accepted telemetry | No | No | No |
| View security events | Yes | Own site | Authorized site |
| Run audit verification | Yes | Read-only view | Yes |
| Resolve anomaly investigation | Yes | Own site | Record audit finding if allowed |
| Change compliance profile | Yes | No | No |
| Run demo attack scenarios | Yes | If demo permission enabled | No |
| Delete audit history | No | No | No |

## 11. UI state labels

Use separate fields and labels:

- Signature: `VALID`, `INVALID`, `UNKNOWN_KEY`, `NOT_CHECKED`.
- Delivery/protocol: `FRESH`, `DUPLICATE`, `REPLAY`, `GAP`, `DELAYED`.
- Witness: `RECEIVED`, `PENDING`, `MISMATCH`, `WITNESS_LAGGING`.
- Sensor availability: `ONLINE`, `STALE`, `OFFLINE`.
- Calibration: `CURRENT`, `EXPIRED`, `UNKNOWN`, `NOT_APPLICABLE`.
- Compliance: `WITHIN_CONFIGURED_LIMIT`, `EXCEEDANCE`, `NOT_EVALUATED`.
- ML: `CONSISTENT`, `SUSPICIOUS`, `NOT_EVALUATED`, `ERROR`.

Never show an overall `VERIFIED` badge if required component states are unknown or pending. Provide a details panel explaining exactly what was verified.

## 12. Accessibility and responsive requirements

- Table headers must be semantic.
- All icon-only buttons need accessible labels.
- Charts need textual summaries and keyboard-accessible data alternatives.
- Use focus states and do not trap keyboard users.
- Layout must work at laptop width and narrow mobile width; dashboard tables may scroll horizontally with proper labels.
- Respect reduced-motion preference.
