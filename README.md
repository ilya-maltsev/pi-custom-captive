# pi-custom-captive

Minimal self-service captive portal for [privacyIDEA](https://www.privacyidea.org/).

A narrow proxy to the privacyIDEA REST API exposing **only**:

- user self-enrollment of a single TOTP token (Google Authenticator compatible);
- one-time-only flow — once a user has ≥1 active TOTP in PI, the portal refuses them until an administrator deletes/unassigns the token;
- admin area (gated by PI password **+** admin TOTP) to list / enable / disable / delete a user's TOTP tokens.

The portal never stores user data — it has **no database**. All state lives in privacyIDEA. Events are emitted as syslog so they can be forwarded to the parent `privacyidea-docker` rsyslog container.

---

## Architecture

```
Browser ──> [ pi-custom-captive :6443 ] ── PI REST API ──> [ reverse_proxy :8443 ] ──> [ privacyidea :8080 ]
```

| Component | Role |
|-----------|------|
| **app** (Django) | renders the portal, calls PI REST |
| **reverse_proxy** (nginx) | TLS termination |
| **PI service account** | used by the portal to list/init/delete tokens |

Only these PI endpoints are called: `/auth`, `/validate/check`, `/token/`, `/token/init`, `/token/<serial>` (DELETE), `/token/enable`, `/token/disable`.

---

## Configuration

See `environment/application-captive.env` for the full list. Key variables:

| Var | Meaning |
|-----|---------|
| `PI_API_URL` | base URL of privacyIDEA REST API |
| `PI_REALM` | the **only** realm the portal operates in |
| `PI_SERVICE_USER` / `PI_SERVICE_PASSWORD` | PI admin account used by the portal |
| `PROXY_PORT` | external HTTPS port (default 6443) |
| `SYSLOG_*` | optional remote syslog forwarding (see pi-vpn-pooler for the same scheme) |

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
