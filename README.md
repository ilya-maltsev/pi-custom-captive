🌐 **English** | [Русский](README.ru.md)

# pi-custom-captive

Minimal self-service captive portal for [privacyIDEA](https://www.privacyidea.org/).

A narrow proxy to the privacyIDEA REST API with exactly two entry points and a deliberately small privilege surface:

- **User flow** — one-shot TOTP self-enrolment. After enrolling, the user is locked out until an admin removes their token.
- **Admin flow** — two-step challenge-response login (password → OTP) entirely on PI's `/auth` endpoint via `transaction_id`. Once authenticated with 2FA, admins land on a realm-wide TOTP token table (sortable, per-column filterable) with enable / disable / delete actions. No credentials ever leave server memory — the password is **never** persisted in the session or round-tripped to the browser.

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

- `/auth` — password and OTP check for **both** steps of admin 2FA (step 1 password → challenge, step 2 `transaction_id` + OTP → JWT) and user password authentication. Returns the JWT the portal uses for the rest of the session.
- `/validate/check` — used only by the user flow to verify the freshly-enrolled TOTP against the just-generated secret. No JWT required.
- `/token/` — list tokens visible to the JWT caller. The admin home page lists all TOTP tokens in the managed realm via `realm=<CAPTIVE_PI_REALM>&type=totp`.
- `/token/init` — enrol a TOTP. When called on a user's JWT it enrols for that user; when called on an admin's JWT it can target any user via `user=`.
- `/token/<serial>` DELETE, `/token/enable`, `/token/disable`, `/token/reset` — admin mutations; run on the admin's JWT (obtained after full 2FA at login).

---

## PI policy requirements

The admin challenge-response login requires a privacyIDEA policy with:

| Setting | Value |
|---------|-------|
| **Scope** | `authentication` |
| `challenge_response` | `totp` |
| `otppin` | `userstore` |
| `passOnNoToken` | `true` |

This makes PI:
1. Accept the AD/LDAP password as the PIN (`otppin: userstore`).
2. Trigger a TOTP challenge when a valid password is sent for a user who has a TOTP token (`challenge_response: totp`).
3. Let users without tokens authenticate with password alone (`passOnNoToken: true`) — used for first-time admin enrolment.

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

### Admin flow — challenge-response login (no credentials in session)

```
[  Browser  ]                [  captive portal  ]                    [  privacyIDEA  ]
     |                               |                                       |
     |  ─── Step 1: trigger challenge ───                                    |
     |                               |                                       |
     | POST /admin/login/            |                                       |
     |  user, password               |                                       |
     |------------------------------>|                                       |
     |                               | POST /auth                            |
     |                               |  username=<admin>, password=<pw>      |
     |                               |-------------------------------------->|
     |                               |<- 200 {result.status: true,           |
     |                               |   result.value: false,                |
     |                               |   detail.transaction_id: "036300…"}   |
     |                               |                                       |
     |                               | discard password (GC'd after response)|
     |<- 200 OTP form                |                                       |
     |    [username, transaction_id: |                                       |
     |     hidden]                   |                                       |
     |                               |                                       |
     |  ─── Step 2: complete auth ───                                        |
     |                               |                                       |
     | POST /admin/login/            |                                       |
     |  username, transaction_id, otp|                                       |
     |------------------------------>|                                       |
     |                               | POST /auth                            |
     |                               |  username=<admin>,                    |
     |                               |  transaction_id=<tid>,                |
     |                               |  password=<otp>                       |
     |                               |-------------------------------------->|
     |                               |<- 200 JWT (role=admin)                |
     |                               |                                       |
     |                               | session: admin_token=JWT              |
     |<- 302 /admin/                 |                                       |
     |                               |                                       |
     |  ─── Full access (2FA done) ──                                        |
     |                               |                                       |
     | GET /admin/                   |                                       |
     |------------------------------>|                                       |
     |                               | GET /token/?realm=<realm>&type=totp   |
     |                               |-------------------------------------->|
     |                               |<- 200 {tokens: [...]}                 |
     |<- 200 realm-wide TOTP table   |                                       |
     |    (sort/filter, per-row      |                                       |
     |     enable/disable/delete)    |                                       |
     |                               |                                       |
     | POST /admin/token/<s>/delete/ |                                       |
     |------------------------------>|                                       |
     |                               | DELETE /token/<serial>                |
     |                               |     (auth: admin JWT)                 |
     |                               |-------------------------------------->|
     |                               |<- 200                                 |
     |<- 302 /admin/                 |                                       |
```

Key properties of this flow:
- **Password never persisted — anywhere.** The step-1 password is used once for `POST /auth`, then garbage-collected. It is not stored in the session, not encrypted into a cookie, and not re-sent from the browser. Only the `transaction_id` round-trips as a hidden form field.
- **Both steps hit the same endpoint (`/auth`).** The old implementation mixed `/validate/check` (step 1) with `/auth` (step 2) and needed a helper module to encrypt the password between them; that module (and its symmetric key) have been removed.
- **No step-up required.** 2FA is completed during login — all management actions are immediately available.
- **Wrong passwords are caught in step 1.** `POST /auth` raises a `PIClientError` when the password is invalid; a challenge response (`status=true`, `value=false`, `transaction_id` in `detail`) means the password was accepted and OTP is required.

Admins with no TOTP enrolled get through via `passOnNoToken` and are immediately redirected to the enrollment page. After enrolling they must re-login — the next login triggers the challenge-response flow.

### mTLS flow

Header-based identity via a reverse-proxy-verified client certificate is wired in the settings/middleware but **currently disabled in code** because mTLS does not produce a PI JWT and the portal no longer uses a service account. The code path renders a 501 explaining the state. Re-enabling it means either:

- using a PI passthru-by-certificate policy to let `/auth` or `/validate/check` accept the cert as a factor, or
- re-introducing a service account for the mTLS-only branch with an explicit config flag.

Both options are open; `MTLS_*` env vars remain so the scaffold is ready when it's revisited.

---

## Configuration

See `environment/application-captive.env` for the full list. Key variables:

| Var | Default | Meaning |
|-----|---------|---------|
| `PI_API_URL` | `https://host.docker.internal:8443` | base URL of privacyIDEA REST API |
| `PI_REALM` | `defrealm` | legacy realm variable — used when `CAPTIVE_PI_REALM` is unset |
| `CAPTIVE_PI_REALM` | *(empty → falls back to `PI_REALM`)* | realm the portal operates in (user enrolment + admin token table) |
| `CAPTIVE_ADMIN_PREFIX` | `admin` | URL segment for admin endpoints. Set to e.g. `manage` to serve `/manage/`, `/manage/login/`, `/manage/token/<s>/delete/`. No leading/trailing slashes. |
| `DJANGO_LANGUAGE_CODE` | `en` | default UI language when the visitor has no session/cookie selection and no matching `Accept-Language` header. Must be one of `en`, `ru`. |
| `PROXY_PORT` | `6443` | external HTTPS port |
| `OTPAUTH_ISSUER` | `privacyIDEA` | overrides the authenticator app's issuer line (e.g. `VPN-GATE1`) — see below |
| `OTPAUTH_LABEL_ATTR` | `username` | PI user attribute shown as the account line in the authenticator app |
| `TOKEN_SERIAL_PREFIX` | *(empty)* | when set, the portal builds custom PI serials — see below |
| `TOKEN_SERIAL_SUFFIX` | `username` | PI user attribute supplying the middle segment of the custom serial |
| `SYSLOG_*` |  | optional remote syslog forwarding (same scheme as pi-vpn-pooler) |
| `MTLS_*` |  | mTLS header-auth (scaffold present; flow currently returns 501, see above) |

There is intentionally **no** `PI_SERVICE_USER` / `PI_SERVICE_PASSWORD`. The portal never authenticates as anyone other than the actor currently using it.

### Authenticator-app display and token serial

Two independent customisations:

**1. What the user sees in Google Authenticator / Authy / 2FAS.** The otpauth URI the portal encodes into the QR controls the account line. PI's default is `privacyIDEA: TOTP0002702F`, which is not useful to end users. The portal rewrites the URI on the fly:

- `OTPAUTH_ISSUER` (default `privacyIDEA`) → shown as the bold row in the app list.
- `OTPAUTH_LABEL_ATTR` (default `username`) → which PI user attribute becomes the account line under it. `username` requires no extra PI call; other values (`email`, `givenname`, `mobile`, `custom_*`) trigger a `GET /user/` on the user's own JWT — see the policy note below.

Example: `OTPAUTH_ISSUER=VPN-GATE1 OTPAUTH_LABEL_ATTR=username` makes the authenticator app show **VPN-GATE1 · LatrStr**.

The enrolment screen also exposes the raw base32 secret in a click-to-copy block (grouped `ABCD EFGH IJKL …`) for users whose devices can't scan the QR — no more hidden "Show setup URI" details.

**2. What PI stores as the token serial.** By default PI assigns `TOTPXXXXXXXX` which is opaque to admins. When `TOKEN_SERIAL_PREFIX` is set, the portal passes a pre-built `serial=` to `/token/init` in the form:

```
{TOKEN_SERIAL_PREFIX}-{SANITIZED(user.<TOKEN_SERIAL_SUFFIX>)}-{SHORT_HASH}
```

- `SANITIZED(…)` keeps only `[A-Z0-9]` and uppercases.
- `SHORT_HASH` is 6 random hex chars — prevents sanitisation collisions (e.g. `a.b` and `ab` both collapsing to `AB`) and keeps re-enrolments distinguishable in the PI audit log.
- If `TOKEN_SERIAL_SUFFIX=""` the middle segment is omitted: `{PREFIX}-{HASH}`.

Example with `TOKEN_SERIAL_PREFIX=VPN-GATE1 TOKEN_SERIAL_SUFFIX=username` and user `SrinPur`:

```
VPN-GATE1-SRINPUR-8240DC
```

Admins scanning PI can now group tokens by prefix (`VPN-GATE1-*`) and read off who owns each one at a glance.

> [!NOTE]
> **PI policy requirement for non-username attributes.** Looking up `email` / `givenname` / `mobile` via `/user/?username=<self>` requires the user-scope PI policy to grant the `userlist` action. The dev seed in `privacyidea-docker` does not grant it, so non-username attributes silently fall back to the login username — the portal logs `attr=<X> not found on user=<U>; using fallback` and the enrolment still succeeds. In production, add an authentication-scope or user-scope policy with `action=userlist` scoped to the realm if you want to use these attributes.

---

## Internationalisation (i18n)

The portal supports Russian and English. The default language is set via the `DJANGO_LANGUAGE_CODE` env var (default `en`). Users can switch language via the topbar buttons.

Translation files live in `locale/ru/LC_MESSAGES/django.po`. After editing the `.po` file, recompile:

```bash
msgfmt -o locale/ru/LC_MESSAGES/django.mo locale/ru/LC_MESSAGES/django.po
```

When running in Docker, rebuild the image so the `.mo` file is baked in.

---

## Quick start

```bash
make secrets                       # generate DJANGO_SECRET_KEY
# edit environment/application-captive.env
make cert                          # self-signed TLS for the nginx reverse proxy
make stack                         # run production compose
```

Open `https://localhost:6443/` for the user portal, `https://localhost:6443/admin/login/` for the admin area (or `/<CAPTIVE_ADMIN_PREFIX>/login/` if you changed the prefix).

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
- The admin flow is never affected by `MTLS_ENABLED`. Admins still log in with password and complete 2FA via challenge-response.
