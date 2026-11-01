# EnviroTrust — Human Authentication, Role-Based Access Control & Site-Scoped Authorization

## 1. Overview & Architectural Boundaries

EnviroTrust separates machine identities from human identities:

- **Machine Identities (Sensors & Operations Sources)**:
  - Cryptographically identified via pre-provisioned asymmetric Ed25519 key pairs (`PH-OUT-001`, `COD-OUT-001`, `TSS-OUT-001`, `OPS-001`).
  - Every telemetry reading, heartbeat envelope, and operational context payload is canonicalized using RFC 8785 (JCS) and signed with the private key.
  - Ingestion endpoints (`/api/v1/ingestion/*`) verify Ed25519 digital signatures and replay sequence cursors. They **never** require human JWT authentication.
- **Human Identities (Platform Users, Operators, Auditors)**:
  - Authenticated via email and password credentials hashed using `bcryptjs` (salt rounds 10).
  - Issues short-lived JWT access tokens (15 minutes) and rotating `HttpOnly` refresh session cookies (7 days).
  - Refresh tokens are stored in the database **strictly as SHA-256 cryptographic hashes**, never as raw tokens.
  - Role-based permissions and site memberships are enforced by centralized middleware across all human-facing read and administrative endpoints.

---

## 2. User Roles & Capabilities

| Capability | PLATFORM_ADMIN | FACTORY_OPERATOR | REGULATOR_AUDITOR |
| :--- | :---: | :---: | :---: |
| **Global View Across All Sites** | **Yes** | No | No |
| **View Assigned Site Telemetry** | Yes | Yes | Yes (Read-only) |
| **View Sensor Availability & Heartbeats** | Yes | Yes | Yes (Read-only) |
| **View Security Events & Alerts** | Yes | Yes (Assigned) | Yes (Assigned) |
| **View Station Audit Hash Chains** | Yes | Yes (Assigned) | Yes (Assigned) |
| **View Witness Checkpoints & Reconcile** | Yes | Yes (Assigned) | Yes (Assigned) |
| **Export Audit Evidence** | Yes | Yes (Assigned) | Yes (Assigned) |
| **Manage Users & Site Memberships** | **Yes** | No | No |
| **Deactivate User Accounts** | **Yes** | No | No |
| **Modify Accepted Telemetry** | **No (Immutable)** | **No (Immutable)** | **No (Immutable)** |
| **Modify Witness Event History** | **No (Immutable)** | **No (Immutable)** | **No (Immutable)** |

### PLATFORM_ADMIN
- Unrestricted platform-wide access to all sites, monitoring stations, sensors, and audit logs.
- Can create and deactivate human user accounts, assign roles, and configure site memberships.
- Cannot alter immutable signed telemetry records or tamper with witness hash chains.

### FACTORY_OPERATOR
- Strictly restricted to assigned sites configured in `user_site_memberships`.
- Authorized to inspect real-time sensor health, telemetry, operational context, security alerts, and heartbeat histories for assigned facilities.
- Cannot access unassigned sites, create administrator accounts, or modify historical measurement data.

### REGULATOR_AUDITOR
- Read-only inspection access to assigned sites.
- Authorized to inspect telemetry, sensor availability, audit hash chains, and independent witness verification checkpoints.
- Cannot modify system configuration, register keys, or alter data.

---

## 3. Authentication Architecture & Token Lifecycle

```
[ Human User / Client ]
         │
         │  1. POST /api/v1/auth/login { email, password }
         ▼
[ Primary API — AuthService ]
         │
         ├──► 2. Normalize email: lower(trim(email))
         ├──► 3. Check failed attempt rate limiter (5 max per 15 min)
         ├──► 4. Verify password with bcrypt.compare()
         ├──► 5. Verify account status == 'ACTIVE'
         ├──► 6. Load site memberships from user_site_memberships
         ├──► 7. Generate JWT access token (15m expiry, HS256)
         ├──► 8. Generate 320-bit cryptographically secure random refresh token
         ├──► 9. Store SHA-256(refreshToken) in authentication_sessions
         ├──► 10. Record LOGIN_SUCCESS audit event (no secrets logged)
         │
         ▼
[ Response 200 OK ]
  - Body: { accessToken, user: { id, email, role, sites } }
  - Set-Cookie: envirotrust_refresh=<rawRefreshToken>; HttpOnly; SameSite=Lax; Path=/api/v1/auth
```

### Refresh Token Rotation & Reuse Detection
- When `POST /api/v1/auth/refresh` is called:
  1. The incoming refresh token is hashed via SHA-256.
  2. The session record is queried by `token_hash`.
  3. **Reuse Detection**: If the session is found but `revoked_at IS NOT NULL`, a replay attack is detected (an already rotated or revoked token is being reused). The server **immediately revokes all active sessions for that user** and logs a `REFRESH_TOKEN_REUSE_DETECTED` security audit event.
  4. If valid, the old session is marked `revoked_at = now()`, a new refresh token and session row are generated, and a new JWT access token is issued.
- When `POST /api/v1/auth/logout` is called:
  1. The active session is marked `revoked_at = now()`.
  2. The `envirotrust_refresh` cookie is cleared.
  3. A `LOGOUT` audit event is recorded.

---

## 4. Site-Scoped Authorization Rule

> [!CRITICAL]
> **Client-provided parameters are scopes, never permissions**:
> Query parameters (`?siteId=PLANT-002`) and request headers (`X-Site-Id: PLANT-002`) represent requested filters. They **never** grant access by themselves.
> The backend authorization middleware (`requireSiteAccess`) validates the requested resource's site directly against the authenticated user's database-verified permissions (`req.user.sites`).
> If a user attempts to access a sensor, history record, or health status for an unassigned site, the API returns a strict `403 FORBIDDEN` (`FORBIDDEN_SITE_ACCESS`) without disclosing resource existence.

---

## 5. Protected API Endpoints

| Endpoint | Method | Authentication | Authorization Policy |
| :--- | :--- | :--- | :--- |
| `/api/v1/auth/login` | `POST` | Public (Rate-limited) | Anonymous |
| `/api/v1/auth/refresh` | `POST` | Refresh Token Cookie | Active Session |
| `/api/v1/auth/logout` | `POST` | Refresh Token Cookie | Active Session |
| `/api/v1/auth/me` | `GET` | Bearer JWT | Authenticated User |
| `/api/v1/sensors/health` | `GET` | Bearer JWT | Site-scoped (Admin: All; Operator/Auditor: Assigned) |
| `/api/v1/sensors/:sensorId/health` | `GET` | Bearer JWT | Site-scoped |
| `/api/v1/heartbeats/history` | `GET` | Bearer JWT | Site-scoped |
| `/api/v1/ingestion/readings` | `POST` | None (Machine) | Ed25519 Sensor Signature |
| `/api/v1/ingestion/operations-context` | `POST` | None (Machine) | Ed25519 Ops Signature |
| `/api/v1/ingestion/heartbeats` | `POST` | None (Machine) | Ed25519 Sensor Signature |

---

## 6. Demo User Provisioning

Demo accounts can be initialized using the CLI script `scripts/seed-users.ts`:

```powershell
# Ensure local development database is running and migrated
$env:PATH = "$pwd\.tools\node-v24;$env:PATH"
npm run db:migrate

# Provision initial demo accounts
npm run users:seed
```

### Pre-configured Demo Accounts

| Email | Role | Assigned Sites | Default Development Password |
| :--- | :--- | :--- | :--- |
| `admin@envirotrust.local` | `PLATFORM_ADMIN` | `PLANT-001`, `PLANT-002` (Global) | `DemoPassword123!` |
| `operator@envirotrust.local` | `FACTORY_OPERATOR` | `PLANT-001` | `DemoPassword123!` |
| `auditor@envirotrust.local` | `REGULATOR_AUDITOR` | `PLANT-001` | `DemoPassword123!` |

> [!WARNING]
> Do not use `DemoPassword123!` in production. The password can be customized via the `DEMO_USER_PASSWORD` environment variable when provisioning.

---

## 7. Known Security Limitations & Future Hardening

1. **In-Memory Rate Limiting**: The login rate limiter uses an in-memory sliding window per process. In a distributed multi-node deployment, this should be backed by a distributed cache or database table.
2. **Short-Lived Access Tokens**: Access tokens expire in 15 minutes. An immediate revocation of an access token before its 15-minute expiration requires maintaining a token denylist or verifying `token_version` on each request if instant revocation is required.
3. **Local Self-Registration**: Self-registration is deliberately disabled in this prototype. User creation is strictly managed by administrators or initialization scripts.

