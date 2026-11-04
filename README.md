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
| `GET`  | `/nip-fa/v1/login/start` | Buzz NIP-FA browser login: validates the loopback `return_to` and S256 handoff challenge, then joins the Moneta login (only when `BUZZ_ADAPTER_ENABLED`) |
| `POST` | `/nip-fa/v1/login/exchange` | Buzz NIP-FA code exchange: single-use code + handoff secret for an adapter session |
| `GET`  | `/nip-fa/v1/session` | Buzz NIP-FA session check (Bearer adapter session), revalidated against Cognito at most hourly |
| `GET`  | `/nip-fa/v1/identity/key` | Our extension to NIP-FA (Bearer adapter session): returns the platform-held Nostr key `{nostr_pubkey, secret_key}` for the session's mPass ID, the same key on every device |
| `POST` | `/nip-fa/v1/identity/assertions` | Buzz NIP-FA relay assertion (Bearer adapter session + `Nostr-Authorization` NIP-98 proof): returns a short-lived NIP-FI assertion `{assertion, nostr_pubkey, expires_at}` for an allowlisted relay |
| `GET`  | `/.well-known/jwks.json` | Public signing key, served when `LAUNCHPAD_EMAIL_CAPTURE` or `BUZZ_ADAPTER_ENABLED` is on (404 otherwise) |

### Traefik routing — cross-repo invariant

Every endpoint above **must** have a matching `Path()` entry in the `mpass-bridge`
Traefik router rule. A path missing from that rule falls through to the
oauth2-proxy catch-all, which answers with a `302` to the login page —
machine-to-machine callers (MCP OAuth token exchange) cannot follow a redirect,
so auth breaks silently rather than erroring.

The router rule does **not** live in this repository. It is the
`traefik.http.routers.mpass-bridge.rule` label on the `mpass-auth-proxy` service
in `docker-compose.yml` in `Pressingly/foss-server-bundle` (private), and it
currently lists exactly the six non-`/nip-fa/` paths in the table above other
than `/.well-known/jwks.json`, which oauth2-proxy reads on the internal network.
Every Buzz adapter route lives under `/nip-fa/` (see `nip_fa/`), so the rule needs
one `PathPrefix(`/nip-fa/`)` for all of them rather than a `Path()` per route. A
Buzz relay that fetches the JWKS from the adapter's public origin also needs
`Path(`/.well-known/jwks.json`)` on that router.

So adding, renaming or removing a route here is a **two-repo change**: land the
route in this repo, then open a coordinated PR against foss-server-bundle
updating the rule. The route is not reachable in any deployment until both have
shipped. If you do not have access to that repo, say so on your PR so someone who
does can pair the change.

## Configuration

All configuration is read from the environment at import time; the required
variables have no defaults and the process fails fast if they are missing. See
[`.env.example`](.env.example) for the full list with descriptions.

Required: `OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `MONETA_HOSTED_UI_URL`,
`MPASS_CALLBACK_URL`, `REDIS_URL`, `COOKIE_DOMAIN`.

Optional: `OIDC_CLIENT_SECRET`, `SESSION_COOKIE_MAX_AGE_SECONDS`,
`OIDC_LOGOUT_URI`, `LOGOUT_REDIRECT_URL`, `SMB_CORPORATE_ID`, `PORTAL_URL`,
`LOG_LEVEL`.

The Buzz NIP-FA adapter (`BUZZ_ADAPTER_ENABLED`, off by default) requires
`BUZZ_IDENTITY_MASTER_SECRET` (64 hex characters), `BUZZ_IDENTITY_SALT` (hex,
32 to 128 characters) and `LAUNCHPAD_DB_PASSWORD`, and reads the optional
`BUZZ_ADAPTER_SESSION_TTL_SECONDS` (default 2592000, 30 days). The service
refuses to start with the flag on and any of the three missing or malformed.

Each user's Nostr key is
`HKDF-SHA256(ikm=master secret, salt=identity salt, info="moneta-buzz/nostr-key/v1|" + uint16_be(len(mPass ID)) + mPass ID + attempt byte)`,
where the attempt byte is 0 unless that scalar is out of range for secp256k1,
so changing either value re-keys every Buzz user. The first issuance binds the
public key in launchpad's `buzz_identities` table; a later derivation that no
longer matches it is refused with `binding_mismatch` rather than issuing a new
identity. The master secret also seals the adapter's Redis records, so rotating
it signs every Buzz session out.

### Buzz relay assertions

`POST /nip-fa/v1/identity/assertions` issues the NIP-FI assertion a Buzz client
presents to a relay. It needs:

- `BUZZ_NIP_FI_ISSUER` (required): the exact `iss` string, an https URL with no
  trailing slash. It must differ from `MPASS_PROXY_ISSUER_URL`.
- `BUZZ_RELAY_URLS` (required): comma-separated canonical relay URLs,
  `wss://host[:port]` in lowercase, default port omitted, no port 80, no trailing
  slash, path, query or fragment. A non-canonical entry refuses startup; requests
  are compared against the list exactly.
- `BUZZ_ASSERTION_TTL_SECONDS` (default 300, 30 to 3600): assertion lifetime,
  capped by the adapter session's expiry.
- `BUZZ_ADAPTER_PUBLIC_ORIGIN` (optional): the origin Buzz clients reach this
  service on. The NIP-98 `u` tag must equal `<origin>/nip-fa/v1/identity/assertions`
  exactly. It defaults to the `MPASS_CALLBACK_URL` origin; behind Traefik the
  request URL is the internal one, so it is never used.
- A signing key: assertions are RS256 with the same key and `kid` email capture
  uses, so with the adapter on the service loads it (and serves the JWKS) even
  with capture off, from the sources `.env.example` lists.

Each Buzz relay's NIP-FI issuer policy must match, or the relay rejects every
assertion:

| Relay setting | Value |
|---|---|
| issuer | `BUZZ_NIP_FI_ISSUER`, byte for byte |
| `jwks_uri` | `<adapter origin>/.well-known/jwks.json` |
| token class | dedicated NIP-FI (`typ` `nip-fi+jwt`), `RS256` |
| community audience | `https://` + the relay URL's authority, e.g. `wss://chat.example.com` → `https://chat.example.com` |
| `maximum_assertion_age_seconds` | at least `BUZZ_ASSERTION_TTL_SECONDS` |

Requests are limited to 30 per adapter session per 60 seconds (`429
rate_limited` with `Retry-After`). The claims are `iss`, `sub` (the mPass ID),
`aud`, `iat`, `exp`, `nostr_pubkey` and, when the email local part meets the
relay's username rules, `nostr_public_profile` `{display_name, username}`.

**Deploy order:** `buzz_identities` and its grants come from launchpad-api's
`sql/schema.sql`. Apply that schema (`python -m src.migrate`) before enabling
the adapter here, or `/nip-fa/v1/identity/key` and `/nip-fa/v1/identity/assertions`
answer `503 issuance_unavailable`.

Launchpad email capture (`LAUNCHPAD_EMAIL_CAPTURE`) adds its own required set:
the signing key (`MPASS_SIGNING_KEY_B64` or the `MPASS_SIGNING_KEY_GCP_*` pair),
`SYNTHETIC_EMAIL_DOMAIN` and `LAUNCHPAD_DB_PASSWORD`. The other `LAUNCHPAD_DB_*`
values default to the bundle's postgres. `.env.example` describes each one and
the order the key sources are tried in.

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
