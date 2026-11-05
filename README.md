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
| `POST` | `/nip-fa/v1/nip-fi/agent-grant` | Buzz NIP-FA agent grant (RFC 8693 form with the owner's session as `subject_token`, a NIP-OA `owner_attestation`, and a NIP-98 proof by the agent key): enrolls the agent and returns an opaque grant (only when `BUZZ_AGENTS_ENABLED`) |
| `POST` | `/nip-fa/v1/nip-fi/agent-assertion` | Buzz NIP-FA agent assertion (Bearer agent grant + NIP-98 proof by the agent key): returns a `nip-fi-agent+jwt` carrying `nostr_owner_pubkey` |
| `POST` | `/nip-fa/v1/nip-fi/agent-revoke` | Buzz NIP-FA agent revocation (Bearer owner session, form `agent_pubkey`): revokes the agent for good and disconnects it on every relay |
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
currently lists every non-`/nip-fa/` path in the table above, including
`/.well-known/jwks.json`. Every Buzz adapter route lives under `/nip-fa/` (see
`nip_fa/`), so the rule needs one `PathPrefix(`/nip-fa/`)` for all of them rather
than a `Path()` per route; that is the only addition the adapter needs there.

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

### Buzz agent keys

`BUZZ_AGENTS_ENABLED` (off by default, read only with the adapter on) turns on
the NIP-FA "Agent keys" routes, following `docs/nips/NIP-FA.md` in block/buzz
at b14899f. With it off they answer `403 agent_unsupported`, so the adapter
never needs the settings below to start.

- An owner enrolls an agent key with their adapter session (as `subject_token`,
  never a header), a NIP-OA `auth` tag signed by their platform-held key, and a
  NIP-98 proof signed by the agent key. Only empty attestation conditions are
  accepted. An agent key belongs to its first owner for good, a revoked one
  never enrolls again, a user's own Buzz key can never be an agent, and each
  user may hold `BUZZ_MAX_AGENTS_PER_USER` unrevoked agents (default 5).
- The grant is opaque; launchpad's `buzz_agents` stores only its SHA-256. It
  lasts `BUZZ_AGENT_GRANT_TTL_SECONDS` (default 691200, 8 days), use does not
  extend it, and enrolling again replaces it.
- Agent assertions have `typ` `nip-fi-agent+jwt`, `sub` the owner's mPass ID
  and `nostr_owner_pubkey` the owner's key, with `exp` capped by the grant.
  They stop the moment the agent is revoked, or its owner's
  `buzz_identities.revoked_at` is set.
- NIP-98 proofs on the grant and assertion routes are single-use (event ids are
  remembered in Redis for 95 seconds, which covers clock drift between replicas).
- Revoking signs a NIP-FI disconnect command (`typ` `nip-fi-command+jwt`, same
  key and `kid`) and sends it to every relay's internal URL. The deny lasts
  `BUZZ_ASSERTION_TTL_SECONDS`, outlasting every assertion already issued. If
  any relay does not confirm, the revocation stands but the route answers `503`
  so the client retries, and a repeated revoke sends the disconnect again.

**Do not turn `BUZZ_AGENTS_ENABLED` on before owner revocation ships.** A grant
is not tied to the owner's adapter session, and nothing in this service sets
`buzz_identities.revoked_at` yet: an owner whose mPass access ends (Cognito
`invalid_grant`, corporate-ID gate) loses their sessions at the next hourly
revalidation, but their agents keep getting assertions until the grant expires
(up to `BUZZ_AGENT_GRANT_TTL_SECONDS`). Owner revocation must set that column
and disconnect the owner's agents before the flag is on anywhere.

`/nip-fa/v1/nip-fi/agent-assertion` looks a well-formed grant up in the
launchpad database before any per-grant limit applies, on the pool email capture
shares. Put a per-client rate limit on that path at the edge.

It needs `BUZZ_RELAY_INTERNAL_URLS` (one per `BUZZ_RELAY_URLS` entry, same
order) and `BUZZ_COMMAND_PRINCIPAL`, and optionally
`BUZZ_RELAY_COMMAND_AUDIENCES`; `.env.example` describes each. Each relay's
issuer policy then also needs:

| Relay setting | Value |
|---|---|
| `command_audiences` | `https://` + the relay URL's authority, or that relay's `BUZZ_RELAY_COMMAND_AUDIENCES` entry |
| `authorized_principals` | `BUZZ_COMMAND_PRINCIPAL` |
| `maximum_command_age_seconds` | 1 to 60 (commands are sent as soon as they are signed) |
| `maximum_assertion_age_seconds` and `skew_seconds` | `maximum_assertion_age_seconds` + `skew_seconds` above `BUZZ_ASSERTION_TTL_SECONDS` by at least the clock drift between this service and the relay. A disconnect's `until` is `now + BUZZ_ASSERTION_TTL_SECONDS` by this service's clock, and the relay refuses one past its own `now + skew + maximum_assertion_age`, so with no margin every revoke answers `503` |
| token class | the dedicated NIP-FI class above, which admits `nip-fi-agent+jwt` too |

Requests are limited to 10 grants and 10 revocations per adapter session and 30
assertions per grant, per 60 seconds.

**Deploy order:** `buzz_identities` and its grants come from launchpad-api's
`sql/schema.sql`. Apply that schema (`python -m src.migrate`) before enabling
the adapter here, or `/nip-fa/v1/identity/key` and `/nip-fa/v1/identity/assertions`
answer `503 issuance_unavailable`. The same goes for `buzz_agents` before
`BUZZ_AGENTS_ENABLED`.

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
