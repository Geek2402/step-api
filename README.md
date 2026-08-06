# Step — Authentication as a Service

Multi-tenant FastAPI backend that provides two-factor authentication (MFA via email OTP)
as a service: developers who use it delegate the entire authentication flow of their own
end users to Step, without having to reimplement password hashing, OTP, JWT, rate limiting,
or an audit trail.

## Table of contents

- [Concept](#concept)
- [Authentication flow](#authentication-flow)
- [Permission model](#permission-model)
- [Architecture](#architecture)
- [Route overview](#route-overview)
- [Security](#security)
- [Installation](#installation)
- [Environment variables](#environment-variables)
- [Running the server](#running-the-server)
- [Swagger documentation](#swagger-documentation)
- [Tests](#tests)
- [Seed script](#seed-script)
- [Roadmap](#roadmap)

## Concept

Three types of actors:

- **User** — a developer (or an admin, distinguished by `is_admin`) who signs up on the
  Step platform and creates **Apps**. This is their own account, protected by the standard
  MFA flow (password + email OTP).
- **App** — represents a third-party application created by a User. Each App has a unique
  **secret token** (`secrets.token_urlsafe`), shown in clear text only once at creation
  (or at rotation). This token acts as a server-to-server credential: it is used by the
  integrating developer's backend (`X-App-Token` header), never directly by the end user.
- **EndUser** — the end user of the developer's App. Scoped by `app_id`: email uniqueness
  is checked per App, not globally (the same email can exist on two different Apps without
  collision). All `/v1/end-users/*` routes require the `X-App-Token` header corresponding
  to the App in question.

Every significant action (signup, login, failed login, read, update, activation, deletion,
rate limit exceeded, permission denied...) is traced in an **AuditLog**, readable by admins
(full history) and by developers for their own Apps.

## Authentication flow

Identical for User and EndUser (only the `X-App-Token` header changes things on the
EndUser side):

```
POST .../auth/login        → email + password → 200 + OTP sent by email
POST .../auth/verify-otp   → email + code      → JWT
POST .../auth/logout       → Authorization: Bearer <JWT> → revokes the token
```

No refresh token: once the JWT expires (30 minutes by default), the whole flow is repeated.

Forgot-password handling, same principle for both populations:

```
POST .../auth/forgot-password  → email → sends a reset token by email (single-use, 15 min)
POST .../auth/reset-password   → email + token + new password
```

The `forgot-password` message is intentionally neutral ("if this email exists...") so as
not to reveal whether an account exists. The reset link is built using `FRONTEND_URL` (for
Users) or `App.frontend_url` (optional, per App, for EndUsers); if the URL isn't configured,
the email contains the raw token instead of a clickable link — it's up to the integrating
developer to pick whichever option suits them.

## Permission model

| Resource | Route | Who can access it |
|---|---|---|
| User | `POST /v1/users` (signup) | Public |
| User | `GET /v1/users/me` | The logged-in user (themself) |
| User | `GET`/`PATCH`/`DELETE /v1/users/{id}` | Themself or an admin |
| User | `GET /v1/users` (list), `activate`/`deactivate`/`promote-admin`/`demote-admin` | Admin only |
| App | All `/v1/apps/*` routes | The App's creator or an admin |
| App | `GET /v1/apps` | Their own Apps (an admin sees everything by default, `?mine=true` restricts to their own) |
| EndUser | `POST /v1/end-users` (signup) | X-App-Token only (no JWT required) |
| EndUser | `GET /v1/end-users/me` | The logged-in EndUser (themself) |
| EndUser | `GET`/`PATCH`/`DELETE /v1/end-users/{id}` | The EndUser in question, the App's creator, or an admin |
| EndUser | `GET /v1/end-users` (list), `activate`/`deactivate` | App creator or admin |
| AuditLog | `GET /v1/audit-logs` (full history) | Admin only |
| AuditLog | `GET /v1/audit-logs/apps/{app_id}` | The App's creator or an admin |

A deactivated account (`is_active=False`) always gets a `401 Unauthorized` on any protected
route, even with a still-valid JWT.

## Architecture

```
app/
├── core/         # config (pydantic-settings), security (JWT/hash/tokens), rate limiter,
│                 # redis, email, FastAPI dependencies (auth + cross permissions)
├── db/           # async SQLAlchemy engine (asyncpg) + session
├── models/       # User, App, EndUser, AuditLog (SQLAlchemy 2.0 Mapped/mapped_column)
│                 # + enums.py (ActorType, AuditEventType)
├── schemas/      # Pydantic request/response (incl. generic Page[T] for pagination)
├── api/v1/       # routers: users, users_auth, apps, end_users, end_users_auth, audit_logs
│                 # — mounted in router.py
└── services/     # otp_service, password_reset_service, audit_service (Redis + AuditLog)
alembic/          # migrations
test_app.py       # end-to-end test script (see "Tests")
```

Key points:

- **JWT isolation**: two distinct secrets (`JWT_SECRET_USERS` / `JWT_SECRET_END_USERS`) — a
  User JWT can never be accepted on an EndUser route and vice versa.
- **Logout via blacklist**: every JWT has a `jti`; logout blacklists it in Redis until the
  token naturally expires.
- **Centralized permissions** in `app/core/dependencies.py`: `require_admin`,
  `require_app_owner_or_admin` (X-App-Token + User JWT), `get_owned_app` (reusable
  dependency to scope an App to its creator), `authorize_end_user_access` (authorizes
  either the EndUser in question via their own JWT, or the App's creator/an admin via
  User JWT).
- **Systematic auditing**: `log_event()` traces reads, writes, auth failures, triggered
  rate limits, and denied permissions — see `app/models/enums.py` for the full catalog of
  events.

## Route overview

All prefixed with `/v1`.

| Router | Prefix | Content |
|---|---|---|
| `users` | `/users` | Signup, `/me`, CRUD, activation/deactivation, admin promotion/demotion, list (admin) |
| `users_auth` | `/users/auth` | `login`, `verify-otp`, `logout`, `forgot-password`, `reset-password` |
| `apps` | `/apps` | Creation, list (paginated, filterable `?mine=`), CRUD, token rotation, activation/deactivation |
| `end_users` | `/end-users` | Signup (X-App-Token), `/me`, CRUD, list, activation/deactivation |
| `end_users_auth` | `/end-users/auth` | `login`, `verify-otp`, `logout`, `forgot-password`, `reset-password` (all X-App-Token) |
| `audit_logs` | `/audit-logs` | Read-only: full history (admin) and per App (creator/admin) |

All list routes (`GET /v1/users`, `GET /v1/apps`, `GET /v1/end-users`,
`GET /v1/audit-logs*`) are paginated via a generic `Page[T]` model
(`items`, `total`, `limit`, `offset`) — query params `limit` (default 20, max 100) and `offset`.

## Security

- **Passwords** hashed with bcrypt (passlib).
- **App tokens** never stored in clear text: only the SHA-256 hash is in the database.
  Rotation is possible via `POST /v1/apps/{id}/rotate-token` (invalidates the old one
  immediately).
- **OTP** stored in Redis (SHA-256 hashed, 5 min TTL by default), with an attempt limit
  (`OTP_MAX_ATTEMPTS`) that locks the code once exceeded.
- **Anti-brute-force rate limiting** on login routes (User and EndUser), two independent
  Redis windows: 5 failures / 15 min per targeted email, 20 failures / 15 min per source IP.
  `429` response with a `Retry-After` header.
- **Isolated JWTs** per population (distinct secrets) + Redis blacklist on logout via `jti`.
- **Exhaustive AuditLog**: authentication successes and failures, reads, updates,
  activations/deactivations, triggered rate limits, denied access — readable by admins
  and by developers for their own Apps.

## Installation

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env              # then fill in DATABASE_URL, REDIS_URL, JWT secrets, BREVO_API_KEY
```

Prerequisites: PostgreSQL and Redis running (locally or via Docker).

```bash
alembic upgrade head
```

## Environment variables

See `.env.example` for the full file — never commit a real `.env`.

| Variable | Purpose |
|---|---|
| `PROJECT_NAME` | Name displayed in the FastAPI app title |
| `ENVIRONMENT` | `development` / `production` (informational) |
| `FRONTEND_URL` | Optional — base of the password reset link for Users. Empty = raw token sent by email |
| `DATABASE_URL` | PostgreSQL DSN, `asyncpg` dialect (`postgresql+asyncpg://...`) |
| `REDIS_URL` | Redis DSN (OTP, JWT blacklist, rate limiting, reset tokens) |
| `JWT_SECRET_USERS` / `JWT_SECRET_END_USERS` | Distinct secrets per population — never share them |
| `JWT_ALGORITHM` | JWT signing algorithm (`HS256` by default) |
| `ACCESS_TOKEN_TTL_MINUTES` | JWT lifetime (30 min by default) |
| `OTP_TTL_SECONDS` / `OTP_LENGTH` / `OTP_MAX_ATTEMPTS` | OTP config (lifetime, number of digits, attempts before lockout) |
| `APP_TOKEN_BYTES` / `APP_TOKEN_PREFIX` | Config for the random secret generated for each App |
| `BREVO_API_KEY` / `EMAIL_FROM` / `EMAIL_FROM_NAME` | Email sending (OTP, password reset) via the Brevo HTTP API. Empty `BREVO_API_KEY` = dev mode, codes/tokens are just printed in the logs instead of being sent |

## Running the server

```bash
uvicorn app.main:app --reload
```

`GET /health` returns `{"status": "ok"}` once the server is up.

## Swagger documentation

- **`/docs`** — public doc, routes tagged `end-user-auth`/`end-users` only (signup,
  login/OTP, end-user CRUD): to be given to developers integrating the API.
- **`/docs/admin`** — full doc (users, apps, end-users, audit-logs...) — internal use
  only. ⚠️ Should be restricted in production (IP allowlist / basic auth via Nginx or
  Dokku) — "hiding" it via the URL is not enough as the sole protection.

## Tests

`test_app.py` is a standalone end-to-end test script (no test dependency to install:
stdlib only). It starts its own uvicorn instance on a dedicated port (email sending disabled
so that OTP/reset tokens are printed in the logs instead of being sent by real email), runs
about a hundred checks covering all routes, permissions, brute-force protection, and
error handling, then cleans up the data it created.

```bash
python test_app.py
```

Real-time output in the terminal + a full summary in `test_report.md`. Requires
PostgreSQL/Redis running and migrations applied.

## Seed script

`scripts/seed/` populates the database with realistic demo data through the **real running
API** (not direct DB inserts), so the resulting `AuditLog` reflects genuine traffic — every
one of the 44 `AuditEventType` values gets exercised at least once, including failure paths
(wrong password, wrong OTP, rate-limit trips, access-denied, invalid App token).

### Prerequisites

- PostgreSQL, Redis, and the API server itself must already be running (`uvicorn
  app.main:app`) — the script only talks to the API over HTTP plus a couple of read-only
  Redis/DB lookups, it never bypasses the app.
- An **admin** User account and a **dev** (non-admin) User account must already exist
  (sign up via `POST /v1/users` first, then promote one to admin with
  `POST /v1/users/{id}/promote-admin`) — the script never creates these two accounts, only
  the data underneath them.

### Running it

```bash
venv\Scripts\activate        # or: source venv/bin/activate
python -m scripts.seed.run
```

You'll be prompted for the admin's email/password, then the dev's — both verified against
the real `/login` + `/verify-otp` flow (up to 5 attempts each), including a role check
(rejects if the "admin" account isn't actually an admin, or vice versa).

Once authenticated, it's fully automated:

1. Creates 10 Apps per account (half with a `frontend_url`, half without) and 50 EndUsers
   per App (1000 EndUsers total) — skipped for anything that already exists, so the script
   is safe to re-run.
2. If some or all of that static data is already present, you're asked whether to fill in
   what's missing and/or generate a fresh batch of audit-log activity — nothing is
   recreated or duplicated silently.
3. Exercises every `AuditEventType` (auth successes/failures, CRUD, activation/deactivation,
   role changes, rate-limit trips, access-denied, invalid App token, audit-log reads) using
   a mix of the real admin/dev accounts, one disposable throwaway User, and two disposable
   "fictive" Apps created and deleted purely to log `APP_CREATED`/`APP_DELETED` — by the end,
   each account still owns exactly its 10 static Apps and each App still has exactly 50
   EndUsers.
4. Logs out every session it opened.

### How it gets the OTP without reading email

OTP codes are stored in Redis only as a SHA-256 hash
(`otp:{actor_type}:{actor_id}:{purpose}`, see `app/services/otp_service.py`). Since this
project sends real emails via the Brevo API by default, the script can't just read an inbox — instead
it reads that hash directly from the same Redis instance (`REDIS_URL` from `.env`) and
recovers the 6-digit plaintext by a fast local brute force (10⁶ possibilities, a few
seconds), then completes the login through the real `/verify-otp` call. This never touches
`OTP_MAX_ATTEMPTS` (that counter only counts real `/verify-otp` calls). Password-reset
tokens are simpler: `password_reset_service` stores them in Redis in plain text, so the
script just reads them back directly.

If `BREVO_API_KEY` is left empty in `.env`, `email_client.py` skips sending entirely and prints
the code to the server console instead (`[DEV] Email to ...`) — either way, the script's Redis
lookup works without any change.

### Files

- `scripts/seed/seed_data.json` — all static data (App names/URLs, EndUser name pools, the
  deterministic EndUser email template, the default seed password). No secrets, no
  admin/dev credentials. Edit this to change how much data gets generated.
- `scripts/seed/*.py` — one module per concern (`creds.py` credential verification,
  `bulk.py` Apps/EndUsers creation, `audit_flow.py` the audit-log exercise, `cleanup.py`
  final logout, `otp.py`/`db_checks.py`/`http.py`/`state.py`/`config.py` supporting code).

EndUser emails are generated as `eu{index}-{owner}-app{app_index}@mailinator.com` — a real,
valid domain is required here since `email-validator` rejects reserved/special-use TLDs
like `.local` or `.test`.

## Roadmap

- Dokku/Coolify deployment with HTTPS.
- Additional rate limiting on `forgot-password`/`reset-password` (currently only the
  login routes are protected against brute force).
- Configurable export/retention for the AuditLog (automatic purge past a certain age).
