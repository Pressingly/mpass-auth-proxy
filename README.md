# mpass-auth-proxy

OIDC bridge that lets [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy)
sit in front of Moneta's mPass sign-in. Moneta issues tokens through an
implicit-grant QR flow; oauth2-proxy speaks OIDC authorization code + PKCE. This
service translates between the two so oauth2-proxy can own all session
management.

FastAPI + uvicorn, Redis/Valkey for short-lived bridge state.

> This service used to live at `mpass-auth-proxy/` inside
> [Pressingly/foss-server-bundle](https://github.com/Pressingly/foss-server-bundle).
> That copy is deprecated — this repository is the source of truth for all new
> development. Commit history up to the extraction stays in foss-server-bundle.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/authorize` | Receives the oauth2-proxy OIDC redirect, stores the request params (including the PKCE challenge), redirects the browser to the Moneta hosted UI |
| `GET`  | `/mpass-callback` | Moneta returns the `id_token` here; mints a one-time auth code and redirects to oauth2-proxy's `/oauth2/callback` |
| `POST` | `/token` | oauth2-proxy exchanges the auth code (or a refresh token) for real IdP tokens |
| `GET`  | `/mpass/login` | Redirects to `/oauth2/sign_in` — re-initiates SSO after a 401 |
| `GET`  | `/mpass/logout` | Clears the `mpass_bridge` cookie, then `302` to `/oauth2/sign_out`, optionally chaining through the IdP sign-out |
| `GET`  | `/health` | Liveness check |

### Traefik routing

Every endpoint above **must** have a matching `Path()` entry in the deployment's
`mpass-bridge` Traefik router rule. A path missing from the rule falls through to
the oauth2-proxy catch-all, which answers with a `302` to the login page —
machine-to-machine callers (MCP OAuth token exchange) cannot follow that, so auth
breaks silently. Add a route here and you must update the router rule in the same
change.

## Configuration

All configuration is read from the environment at import time; the required
variables have no defaults and the process fails fast if they are missing. See
[`.env.example`](.env.example) for the full list with descriptions.

Required: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `MONETA_HOSTED_UI_URL`,
`MPASS_CALLBACK_URL`, `REDIS_URL`, `COOKIE_DOMAIN`.

Optional: `OIDC_CLIENT_SECRET`, `SESSION_COOKIE_MAX_AGE_SECONDS`,
`OIDC_LOGOUT_URI`, `LOGOUT_REDIRECT_URL`, `SMB_CORPORATE_ID`, `PORTAL_URL`,
`LOG_LEVEL`.

## Running locally

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then fill it in
set -a && . ./.env && set +a
uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info --no-access-log
```

`--no-access-log` is deliberate and is also baked into the Dockerfile: uvicorn's
per-request access lines echoed `/mpass-callback` query strings in full, which
carry the `id_token`, `access_token` and `refresh_token`. Application-level
events are logged through the module logger and remain visible.

## Tests

```bash
pip install -r requirements.txt -r requirements-test.txt
pytest
```

`pytest-dotenv` loads `tests/.env.test` before any test module is imported —
those are fake values, and they must stay in sync with the module-level
constants asserted in `tests/test_main.py`.

## Docker

```bash
docker build -t mpass-auth-proxy .
docker run --rm -p 8000:8000 --env-file .env mpass-auth-proxy
```

The container listens on port `8000` and runs as a non-root user.

## License

GPL-3.0 — see [LICENSE](LICENSE).
