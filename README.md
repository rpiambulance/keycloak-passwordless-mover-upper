# keycloak-passwordless-mover-upper

A small worker that keeps every user's **WebAuthn-passwordless** credential at the
top of their Keycloak credential list.

Keycloak uses credential order as the "try this first" priority at login, but
nothing keeps that order stable — registering a new credential (or an admin
password reset) appends to the end, quietly demoting the passkey. This worker
sweeps a realm every *X* minutes and calls the admin API's
`POST .../credentials/{id}/moveToFirst` on any matching credential that isn't
already at the front.

It only writes when something is actually out of order, so a steady-state realm
generates zero `moveToFirst` calls.

---

## Keycloak setup

Create a **confidential client** in the realm you want swept:

1. Clients → Create client → Client ID `passwordless-mover-upper`
2. Capability config: **Client authentication ON**, **Service accounts roles ON**,
   and turn off Standard flow / Direct access grants (it never logs a human in).
3. Credentials tab → copy the client secret into `KEYCLOAK_CLIENT_SECRET`.
4. Service account roles → Assign role → filter by **clients** → from
   `realm-management`, assign:
   - `view-users` — list users and read their credentials
   - `manage-users` — reorder credentials

If you put the client in `master` instead of the target realm, set
`KEYCLOAK_TOKEN_REALM=master` and assign the equivalent roles from the
`<target-realm>-realm` client.

## Configuration

All configuration is environment variables — see [.env.example](.env.example).

| Variable | Default | Purpose |
| --- | --- | --- |
| `KEYCLOAK_URL` | *required* | Base URL, no trailing slash. Keycloak < 17 needs the `/auth` suffix. |
| `KEYCLOAK_REALM` | *required* | Realm whose users get swept. |
| `KEYCLOAK_CLIENT_ID` | *required* | Service account client id. |
| `KEYCLOAK_CLIENT_SECRET` | *required* | Service account client secret. |
| `KEYCLOAK_TOKEN_REALM` | `KEYCLOAK_REALM` | Realm that issues the token, if the client lives elsewhere. |
| `INTERVAL_MINUTES` | `15` | The *X*. Measured cycle-start to cycle-start. |
| `CREDENTIAL_TYPE` | `webauthn-passwordless` | Set to `webauthn` to promote the 2FA authenticator instead. |
| `DRY_RUN` | `false` | Log what would move without moving it. |
| `RUN_ONCE` | `false` | One sweep, then exit — for driving it from cron instead. |
| `PAGE_SIZE` | `100` | Users per admin-API page. |
| `REQUEST_TIMEOUT` | `30` | Per-request timeout, seconds. |
| `MAX_RETRIES` / `RETRY_BACKOFF` | `3` / `2` | Retries on 429/5xx and connection errors, exponential, honours `Retry-After`. |
| `VERIFY_TLS` | `true` | Set `false` only for a self-signed dev Keycloak. |
| `LOG_LEVEL` | `INFO` | `DEBUG` logs per-user decisions. |
| `INTERVAL_SECONDS` | — | Overrides `INTERVAL_MINUTES`; for testing. |

## Running locally

```bash
cp .env.example .env   # then fill it in
docker compose up
```

Or without Docker:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
set -a; source .env; set +a
DRY_RUN=true RUN_ONCE=true .venv/bin/python -m src.mover
```

**Do a `DRY_RUN=true RUN_ONCE=true` pass first.** It prints exactly which
credentials it would promote, for which users, without touching anything.

## Deploying

`scripts/deploy.sh` builds the amd64 image, pushes it to GHCR, and triggers a
Coolify redeploy — same shape as `rpiambulance/central/scripts/deploy.sh`.

One-time setup:

```bash
cp scripts/.env.deploy.example scripts/.env.deploy   # then fill it in
```

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u ddbruce --password-stdin
```

The token needs the `write:packages` scope. Then:

```bash
./scripts/deploy.sh
```

It tags with the current short commit SHA plus `latest`. Pass an explicit tag as
`./scripts/deploy.sh v1.2.3` to override.

### Coolify side

Create the app as a **Docker Image** resource pointing at
`ghcr.io/rpiambulance/keycloak-passwordless-mover-upper:latest`, set the
environment variables from `.env.example`, and leave the ports empty — this is a
background worker, not a server. Copy the app's UUID into `COOLIFY_APP_UUID`.

If the GHCR package is private, add a registry credential in Coolify (username
`ddbruce`, password = a PAT with `read:packages`).

Health is reported through a Docker `HEALTHCHECK` that reads a heartbeat file
touched after each completed sweep, so a wedged worker gets restarted without
needing an HTTP port.

## Operational notes

- **Cost per sweep is one API call per user**, plus one page-listing call per
  `PAGE_SIZE` users — Keycloak has no way to query users by credential type. At
  ~1,000 users that's ~1,010 requests per sweep, which is why the default
  interval is 15 minutes rather than 1. Size `INTERVAL_MINUTES` against your user
  count, not against how fast you want the fix applied.
- **Users with several passkeys** keep their relative order; all of them are
  moved to the front as a block.
- A user that errors is logged and skipped; the rest of the sweep continues. A
  sweep that fails outright is logged and retried on the next interval — the
  process does not exit.
- Sweeps never overlap. If one runs longer than the interval, the next starts
  immediately afterward and logs a warning.
