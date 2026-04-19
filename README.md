# pi-custom-captive

Minimal self-service captive portal for [privacyIDEA](https://www.privacyidea.org/).

A narrow proxy to the privacyIDEA REST API with exactly two entry points and a deliberately small privilege surface:

- **User flow** — one-shot TOTP self-enrolment. After enrolling, the user is locked out until an admin removes their token.
- **Admin flow** — always logs in, but mutations (enable / disable / delete) require a TOTP step-up against the admin's own token.

The portal has **no database** and **no service account**. Every PI call runs on the actor's own JWT — PI auto-scopes to the JWT caller. Events are emitted as syslog so they can be forwarded to the parent `privacyidea-docker` rsyslog container.

---

## Architecture

```
Browser ──> [ pi-custom-captive :6443 ] ── PI REST API ──> [ reverse_proxy :8443 ] ──> [ privacyidea :8080 ]
```

| Component | Role |
|-----------|------|
| **app** (Django) | renders the portal, calls PI REST on the actor's own JWT |
| **reverse_proxy** (nginx) | TLS termination |

The portal never acts on behalf of a user with higher privileges than the user themselves. The user's JWT does the user's work; the admin's JWT does the admin's work.

Only these PI endpoints are called:

- `/auth` — password check for both flows; returns the JWT the portal uses for the rest of the session.
- `/validate/check` — verifies the freshly-enrolled TOTP (user flow) and the admin's TOTP step-up (admin flow). No JWT required.
- `/token/` — list tokens visible to the JWT caller (auto-scoped for users; admin-scoped lookup by `user=` for admins).
- `/token/init` — enrol a TOTP. When called on a user's JWT it enrols for that user; when called on an admin's JWT it can target any user via `user=`.
- `/token/<serial>` DELETE, `/token/enable`, `/token/disable` — admin mutations; run on the admin's JWT and gated by the admin TOTP step-up.

---

## Workflows

### User flow — one-shot self-enrolment

```
[  Browser  ]                [  captive portal  ]                    [  privacyIDEA  ]
     |                               |                                       |
     | GET /                         |                                       |
     |------------------------------>|                                       |
     |<------------- 200 sign-in form|                                       |
     |                               |                                       |
     | POST / user,password          |                                       |
     |------------------------------>|                                       |
     |                               | POST /auth user,password,realm        |
     |                               |-------------------------------------->|
     |                               |<- 200 JWT (role=user, rights=[..,     |
     |                               |             enrollTOTP, ..])          |
     |                               | store JWT in signed-cookie session    |
     |                               |                                       |
     |                               | GET /token/?type=totp&active=true     |
     |                               |     (auth: user JWT, no user= param)  |
     |                               |-------------------------------------->|
     |                               |<- 200 {tokens: []}                    |
     |                               |                                       |
     |<- 302 /enroll/                |                                       |
     | GET /enroll/                  |                                       |
     |------------------------------>|                                       |
     |                               | POST /token/init                      |
     |                               |     type=totp, genkey=1,              |
     |                               |     hashlib=sha256, otplen=6,         |
     |                               |     (auth: user JWT, no user= param)  |
     |                               |-------------------------------------->|
     |                               |<- 200 {serial: TOTP0002702F,          |
     |                               |         googleurl.value: otpauth://…} |
     |<- 200 QR page                 |                                       |
     |    [ user scans in Google     |                                       |
     |      Authenticator ]          |                                       |
     |                               |                                       |
     | POST /enroll/ otp=123456      |                                       |
     |------------------------------>|                                       |
     |                               | POST /validate/check user,pass=otp,   |
     |                               |     realm  (no JWT)                   |
     |                               |-------------------------------------->|
     |                               |<- 200 authentication=ACCEPT           |
     |                               |                                       |
     |                               | session.flush()                       |
     |<- 302 /done/                  |                                       |
```

Any subsequent `GET /` for the same user repeats the `GET /token/?type=totp&active=true` step; this time `count=1`, so the portal redirects to the **Already enrolled** page. That's the lockout: it stays until an admin deletes the token.

### Admin flow — login, then optional TOTP step-up for mutations

```
[  Browser  ]                [  captive portal  ]                    [  privacyIDEA  ]
     |                               |                                       |
     | POST /admin/login/ user,pass  |                                       |
     |------------------------------>|                                       |
     |                               | POST /auth user,password              |
     |                               |-------------------------------------->|
     |                               |<- 200 JWT (role=admin)                |
     |                               |                                       |
     |                               | GET /token/?user=<admin>&type=totp    |
     |                               |     &active=true   (auth: admin JWT)  |
     |                               |-------------------------------------->|
     |                               |<- 200 {tokens: [<N>]}                 |
     |                               | session: admin_token, admin_2fa_ok=0, |
     |                               |          admin_has_totp=<bool>        |
     |<- 302 /admin/                 |                                       |
     |                               |                                       |
     | GET /admin/user/<u>/          | ← read-only listing, no mutations yet |
     |------------------------------>|                                       |
     |                               | GET /token/?user=<u>&type=totp        |
     |                               |-------------------------------------->|
     |                               |<- 200 {tokens: [...]}                 |
     |<- 200 token table, actions    |                                       |
     |       disabled, "Unlock" link |                                       |
     |                               |                                       |
     | GET /admin/otp/               |                                       |
     |------------------------------>|                                       |
     |<- 200 OTP prompt              |                                       |
     | POST /admin/otp/ otp=...      |                                       |
     |------------------------------>|                                       |
     |                               | POST /validate/check user=<admin>,    |
     |                               |     pass=<otp>   (no JWT)             |
     |                               |-------------------------------------->|
     |                               |<- 200 authentication=ACCEPT           |
     |                               | session: admin_2fa_ok=1               |
     |<- 302 /admin/                 |                                       |
     |                               |                                       |
     | POST /admin/user/<u>/token/<s>/delete/                                |
     |------------------------------>|                                       |
     |                               | DELETE /token/<serial>                |
     |                               |     (auth: admin JWT)                 |
     |                               |-------------------------------------->|
     |                               |<- 200                                 |
     |<- 302 /admin/user/<u>/        |                                       |
```

Admins with no TOTP enrolled in PI cannot elevate; the action buttons stay disabled for the whole session and the topbar shows **👁 read-only**. This is deliberate — a compromised admin password alone must not be enough to reset a user's second factor.

### mTLS flow

Header-based identity via a reverse-proxy-verified client certificate is wired in the settings/middleware but **currently disabled in code** because mTLS does not produce a PI JWT and the portal no longer uses a service account. The code path renders a 501 explaining the state. Re-enabling it means either:

- using a PI passthru-by-certificate policy to let `/auth` or `/validate/check` accept the cert as a factor, or
- re-introducing a service account for the mTLS-only branch with an explicit config flag.

Both options are open; `MTLS_*` env vars remain so the scaffold is ready when it's revisited.

---

## Configuration

See `environment/application-captive.env` for the full list. Key variables:

| Var | Meaning |
|-----|---------|
| `PI_API_URL` | base URL of privacyIDEA REST API |
| `PI_REALM` | the **only** realm the portal operates in |
| `PROXY_PORT` | external HTTPS port (default 6443) |
| `SYSLOG_*` | optional remote syslog forwarding (same scheme as pi-vpn-pooler) |
| `MTLS_*` | mTLS header-auth (scaffold present; flow currently returns 501, see above) |

There is intentionally **no** `PI_SERVICE_USER` / `PI_SERVICE_PASSWORD`. The portal never authenticates as anyone other than the actor currently using it.

---

## Quick start

```bash
make secrets                       # generate DJANGO_SECRET_KEY
# edit environment/application-captive.env
make cert                          # self-signed TLS for the nginx reverse proxy
make stack                         # run production compose
```

Open `https://localhost:6443/` for the user portal, `https://localhost:6443/admin/login/` for the admin area.

For development: `make dev` (runs on `http://localhost:6000`, hot-reload, no TLS).

When run as part of the parent `privacyidea-docker` fullstack, the captive container is reached on `https://localhost:6443/` via the central nginx reverse proxy (`:445 → captive:8000`).

---

## Optional: mTLS header-auth (scaffold)

The portal can skip the user password step and derive identity from a TLS client certificate verified by an upstream nginx. Example nginx snippets live in `templates/nginx-mtls.{http,server}.example.conf`. See the Workflows section above for why this flow currently returns 501 — the scaffold is in place; wiring the identity into a real PI session is the outstanding piece.

### Environment variables

| Var | Default | Meaning |
|-----|---------|---------|
| `MTLS_ENABLED` | `false` | Master switch for the user flow. Admin flow is unaffected. |
| `MTLS_USER_HEADER` | `HTTP_X_SSL_USER` | Django META key carrying the username. |
| `MTLS_VERIFY_HEADER` | `HTTP_X_SSL_VERIFY` | Django META key carrying nginx's `$ssl_client_verify`. |
| `MTLS_REQUIRED_VERIFY_VALUE` | `SUCCESS` | Value the verify header must have to let the request through. |

### OCSP (client-cert revocation)

nginx ≥ 1.19 supports OCSP verification of **client certificates** via `ssl_ocsp on;` (not to be confused with OCSP stapling for the server cert). The responder URL is read from each certificate's AIA extension by default — override with `ssl_ocsp_responder` only if your CA doesn't populate AIA. Cache responses with `ssl_ocsp_cache`. If the responder is unreachable nginx rejects the connection by default; switch to `ssl_crl /etc/nginx/ssl/user-ca.crl;` for CRL-based revocation.

### Security notes

- Do not expose gunicorn (`:8000`) directly when `MTLS_ENABLED=true`. Always put nginx in front.
- The example snippet starts with `proxy_set_header X-SSL-User "";` to clamp an attacker-supplied header before overwriting it with nginx's verified value. Keep that line.
- Pin trusted issuers in `ssl_client_certificate` — do not use the OS root bundle.
- The admin flow is never affected by `MTLS_ENABLED`. Admins still log in with password and elevate via the TOTP step-up.
