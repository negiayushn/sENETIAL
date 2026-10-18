# Sentinel – Phase 1 (Foundation)

Continuous application-security & dependency-intelligence platform (capstone).
This phase delivers: monorepo, Postgres + Redis, Prisma schema/migration, Better Auth
(email/password + GitHub OAuth), an auth-guarded NestJS API, and the Next.js shell.

```
apps/api         NestJS 11 API  (config, Pino, validation, health, Better Auth, AuthGuard)
apps/web         Next.js 16 shell (login, dashboard, targets, findings)
packages/db      Prisma 7 schema, migrations, generated client
docker-compose.yml   Postgres 16 + Redis 7
```

## Quick start

```bash
cp .env.example .env            # then set BETTER_AUTH_SECRET:  openssl rand -base64 32
pnpm install
pnpm infra:up                   # docker compose: postgres + redis
pnpm db:generate                # generate the Prisma client
pnpm db:deploy                  # apply migrations (prisma migrate deploy)
pnpm dev                        # api :4000 + web :3000
```

Open http://localhost:3000, create an account, add a target.
Health: `GET http://localhost:4000/health` (readiness: DB + Redis) and `/health/live`.

### GitHub sign-in (optional)
Create an OAuth app at https://github.com/settings/developers
- Homepage URL: `http://localhost:3000`
- Callback URL: `http://localhost:4000/api/auth/callback/github`

Put the client id/secret in `.env` and restart the API. The button appears on the login page automatically.

## How the Phase 1 requirements map to code

| Requirement | Where |
|---|---|
| docker compose for Postgres + Redis | `docker-compose.yml`, `pnpm infra:up` |
| Prisma + first migration | `packages/db/prisma/schema.prisma`, `migrations/0001_init` |
| Better Auth, email/password + GitHub | `apps/api/src/auth/auth.service.ts` |
| Handler mounted as middleware | `apps/api/src/main.ts` (`/api/auth/*splat`, before body parsers) |
| AuthGuard on all other routes | `auth/auth.guard.ts`, registered as global `APP_GUARD`; opt out with `@Public()` |
| Global validation | `ValidationPipe` in `main.ts` (whitelist, forbidNonWhitelisted, transform) + DTOs |
| Pino logger | `nestjs-pino` in `app.module.ts` (pretty in dev, JSON in prod, cookies redacted, request ids) |
| Config module | `config/env.ts` – zod-validated env, app refuses to boot on bad config |
| Health endpoint | `health/health.controller.ts` |
| Next.js shell | `apps/web/app/**` – login, dashboard, targets, findings |

## Notes
- **Prisma 7** needs a driver adapter; `@sentinel/db` exports `prismaClientOptions()` for that. The generated client is git-ignored: run `pnpm db:generate` after pulling.
- **Better Auth is ESM-only**, the API is CommonJS, so it is loaded with dynamic `import()` (see `auth.service.ts`).
- **Route protection in the web app** (`proxy.ts`, the Next 16 name for middleware) only checks that a session cookie exists. The API guard is the real enforcement.
- Changing the schema later: edit `schema.prisma`, run `pnpm db:migrate --name <change>`.

---

# Phase 2 – Website scanner

New pieces: `packages/core` (`@sentinel/core`), `apps/worker`, migration `0002_scans`, and the `verify` / `scans` API routes.

## Running it

```bash
pnpm infra:up                          # Postgres + Redis (docker compose)
pnpm setup                             # install, generate Prisma client, build shared packages, apply migrations
pnpm dev                               # (re)builds shared packages, then runs api + web + worker
pnpm test                              # core (unit + integration), worker (needs DATABASE_URL, i.e. docker compose up)
```

## Flow

1. `POST /targets` → returns `verification: { recordName, recordValue }`. Publish a TXT record `_sentinel-challenge.<host>` = `sentinel-verify=<token>`.
2. `POST /targets/:id/verify` → 200 and the target is `VERIFIED`; otherwise 422 with the reason and the exact record to publish (limit 10/min/target).
3. `POST /targets/:id/scans` → **202** `{ id, status: "QUEUED" }` immediately. 403 if unverified, 409 if a scan is already queued/running, 429 after 6 scans/hour/target.
4. `GET /scans/:id` to poll, `GET /targets/:id/scans` for history. Findings land in `Finding`, upserted by fingerprint.

## Where the security properties live

| Property | Where | Tested in |
|---|---|---|
| Only public IPs are ever contacted (allow-list on `unicast`, IPv4-mapped IPv6 unwrapped) | `core/src/net/ip.ts` | `ip.test.ts` |
| Validate-and-connect use one DNS resolution (no rebinding window); any bad record rejects | `core/src/net/guard.ts` | `guard.test.ts`, `safe-fetch.test.ts` |
| IP literals / odd encodings (`2130706433`, `0x7f.1`, `[::ffff:…]`) blocked | `safe-fetch.ts` `assertUrlAllowed` | `safe-fetch.test.ts` |
| Only ports 80/443, http(s) only, no URL credentials | `safe-fetch.ts` | `safe-fetch.test.ts` |
| Redirects limited to 5 and to the verified hostname; refused redirects are reported, not followed | `safe-fetch.ts` | `safe-fetch.test.ts` |
| 1 MiB body cap, headers/body/total timeouts, `Accept-Encoding: identity` | `safe-fetch.ts` | `safe-fetch.test.ts` |
| TLS probe goes through the same guard | `core/src/net/tls-probe.ts` | `integration.test.ts` |
| Per-target request pacing + per-scan request budget | `core/src/net/rate-limiter.ts` | `rate-limiter.test.ts`, `integration.test.ts` |
| Verification enforced in API **and** worker; worker reads hostname/owner from the DB, not the job | `apps/worker/src/process-scan.ts` | `process-scan.test.ts` |
| One scan per target at a time; per-target scan rate limit | `apps/api/src/scans/scans.service.ts` | manual e2e |
| Evidence redacted before it is stored | `core/src/redact.ts`, `process-scan.ts` | `misc.test.ts`, `process-scan.test.ts` |

## Adding a check

Implement `Check` (`id`, `async run(ctx): Promise<ScanFinding[]>`) in `packages/core/src/scanner/checks/` and add it to `defaultChecks()`. Use `ctx.get(path)` for HTTP (memoised, rate-limited, SSRF-guarded). Pick a `key` that is **stable between scans** (a header name, cookie name, path) — it is part of the fingerprint; never put counts or dates in it.

---

# Phase 3 – GitHub integration

New pieces: `packages/github` (`@sentinel/github`), the lockfile parser in `packages/core`, `apps/worker/src/process-inventory.ts`, migration `0003_github_inventory`, the `/github/*` and `/repositories/*` API routes, and the **Repositories** page.

## 1. Create the GitHub App

GitHub → Settings → Developer settings → GitHub Apps → **New GitHub App**.

| Setting | Value |
|---|---|
| Homepage URL | your `WEB_URL` |
| **Callback URL** | `<API_URL>/github/callback` |
| **Setup URL** | `<API_URL>/github/callback` |
| **Request user authorization (OAuth) during installation** | **checked** — required, see "Security" below |
| Redirect on update | **unchecked** (an update redirect carries no `state`, so it is rejected) |
| Webhook | Subscribe to the **Push** event. Leave *Active* **unchecked** for now: the receiving endpoint (`POST /webhooks/github`) is Phase 5 |
| Repository permissions | **Contents: Read-only**, **Metadata: Read-only**. Nothing else |
| Where can this app be installed | Any account (or only yours while testing) |

Then: **Generate a private key** (downloads a `.pem`), and copy the App ID, the app's slug (the last part of its public URL), and the OAuth Client ID / Client secret into `.env` (see `.env.example`). With these unset the integration is simply off.

## 2. Use it

`pnpm build && pnpm dev`, open **Repositories → Connect GitHub**, pick repositories, then **Run inventory**. Or via the API:

- `GET /github/install` → `{ url }` to send the browser to. `GET /github/callback` is the Setup URL and redirects back to `/repositories?github=<outcome>`.
- `GET /repositories` · `POST /repositories/:id/inventory` (202; a no-op if one is already queued/running; 10/hour/repo) · `GET /repositories/:id/inventory?take=&skip=&direct=true`
- `POST /github/installations/:id/sync` re-lists repositories · `DELETE /github/installations/:id` forgets the installation and its data.

## What the inventory does

1. Mints an installation token **for that one repository, `contents: read` only**, in memory. Nothing GitHub-secret is ever written to the database (only the numeric installation id).
2. Resolves the default branch's newest commit, reads the **root tree**, and downloads `package-lock.json` and `package.json` through the **Git Blobs API** (works above the 1 MB Contents-API limit). No clone, no `npm install`, no code execution.
3. Parses lockfile v1/v2/v3 into `PackageInstance` rows (`name`, `version`, `path`, `dev`, `optional`, `direct`, `source`, `requires`) inside one `DependencySnapshot` keyed by **(repository, commit SHA, lockfile path)**. Re-running on the same commit changes nothing. The newest 5 snapshots per repository are kept.
4. `direct` = declared by the root `package.json` (dependencies, devDependencies, optionalDependencies) **and installed at the top level** — a nested copy of the same name is transitive. Workspace members' declared dependencies count as direct too.

Repositories without a lockfile, or with only `yarn.lock` / `pnpm-lock.yaml`, end as **No lockfile** with the reason shown (support for those is a later addition).

## Security

- **Installation-id spoofing.** The callback URL carries `installation_id`, which a user can edit. Without a check, anyone could attach someone else's installation. The OAuth `code` GitHub sends is exchanged for a user token and `GET /user/installations` must list that installation, otherwise the callback is rejected. The user token is used once and dropped.
- **CSRF.** `state` is 192 random bits, bound to the signed-in user, stored in Redis for 10 minutes and **consumed on first use**.
- **Worker trust.** Jobs carry only a repository id; the worker reads everything else from the database. Repositories are fetched by numeric id, so renames/transfers cannot redirect a fetch.
- **Hostile lockfiles.** Size cap (25 MiB, checked from the tree entry *before* download), package cap (100 000), `Map`/own-property handling for names like `__proto__`, and nothing is ever executed.
- **Failures are classified.** Network/5xx/rate-limit errors retry (3 attempts, exponential backoff); 401/403/404 and unparsable lockfiles fail immediately with a fixed, user-safe message — raw GitHub text is never shown.


> **Troubleshooting: the web app shows `ERR_CONNECTION_REFUSED` for `:4000`.** The API is not running. Look at the API's terminal output: the usual cause is TypeScript errors such as `Property 'repository' does not exist on type 'PrismaService'`, which means the shared packages (`@sentinel/db`, `@sentinel/core`, `@sentinel/github`) are not built or the Prisma client is stale. Run `pnpm build:packages` (or just `pnpm dev`, which now does it). If the API starts but pages return 500, the migrations have not been applied: `pnpm db:deploy`.

---

# Phase 4 – OSV vulnerability matching

New pieces: `packages/core/src/osv/*` (client, advisory normalisation, CVSS, semver matcher), `inventory/graph.ts` (dependency paths), `apps/worker/src/process-match.ts`, migration `0004_advisories_matching`, `POST /repositories/:id/match`, and vulnerability counts / details in the UI.

## Flow

Every successful inventory enqueues a **match** job (also available as **Re-check vulnerabilities**). The worker:

1. Takes the newest snapshot's registry packages (git/file/tarball dependencies have no advisories and are skipped) and asks OSV `POST /v1/querybatch` in chunks of 500, following `next_page_token` for any query that has one.
2. The response is IDs plus `modified` only, so it fetches `GET /v1/vulns/{id}` for advisories it has not cached or whose `modified` is newer than the cached copy, and stores them in `Advisory`.
3. **Confirms each hit with its own range matcher** (`semver` against `affected[].ranges` events + the explicit `versions` list). Where OSV says "affected" but the matcher disagrees, the finding is kept but marked **POTENTIAL** (`evidence.matcher = "osv-only"`); otherwise **CONFIRMED**.
4. Upserts one finding per **(advisory, package)** with: severity, the **smallest fixed version above the installed one**, and for transitive dependencies the **chain from the direct dependency** (`express@4 → accepts@1 → negotiator@0.6`), plus the matching remediation text (including an `overrides` snippet when no parent release exists yet).

## Details worth knowing

- **Severity.** OSV exposes CVSS as a *vector string*, not a number, so the CVSS v3.0/3.1 base score is computed (`core/src/osv/cvss.ts`, tested against published scores) and banded Critical ≥ 9, High ≥ 7, Medium ≥ 4, Low > 0. If there is no v3 vector (v2/v4 only, or none) it uses the advisory's `database_specific.severity` (GitHub's "MODERATE" = Medium); if there is neither it falls back to Medium and records `severity.source = "default"`.
- **Range semantics** follow the OSV spec: events sorted by version, `introduced` turns "affected" on, `fixed` / `last_affected` turn it off; several introduced/fixed pairs are disjoint ranges (e.g. minimist `<0.2.4` and `>=1.0.0 <1.2.6`, and `0.5.0` is correctly *not* affected). A "fixed" version that another range of the same advisory still marks affected is skipped.
- **Finding lifecycle.** The fingerprint is `(advisory, package)`, **not** including the version, so upgrading between two still-vulnerable versions keeps the same finding (and your triage). A finding becomes **FIXED** when the package stops being affected, **REOPENED** if it comes back, and **IGNORED** is never overridden.
- **Outages cannot hide vulnerabilities.** "No longer present ⇒ FIXED" only runs after every OSV call succeeded. On a transient error the job retries (4 attempts, exponential backoff); on the final failure the snapshot shows *Failed* and existing findings are left untouched.
- **Not in this phase:** the local advisory *mirror* and 6-hourly sync (Phase 5; the `Advisory` table is already indexed by package name with a GIN index for it).

## Testing note

`api.osv.dev` was not reachable from the environment this was built in, so OSV behaviour is tested against a local server that speaks the same API, using abbreviated records modelled on real advisories (lodash CVE-2021-23337 / CVE-2020-8203, minimist CVE-2021-44906). Run one real inventory + match against a repository with an old `lodash` before relying on it.
