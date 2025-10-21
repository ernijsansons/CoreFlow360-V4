# CoreFlow360 V4 – Infrastructure & DX Audit

## Snapshot
- **Runtime:** Cloudflare Workers (Wrangler `main = src/index.production.ts`, `compatibility_flags = ["nodejs_compat"]` – `wrangler.toml:3`).
- **Data/Storage:** D1 databases bound multiple times with identical IDs (`wrangler.toml:23`, `wrangler.toml:29`, `wrangler.toml:108`), KV namespaces for cache/session/auth, R2 buckets for documents/backups, Vectorize index bindings.
- **Routing:** Dual stack – `itty-router` handles outer worker (`src/index.ts:66`), Hono mounts API modules under `/api/v1` (`src/routes/index.ts:63`).
- **Serverless services:** Durable Objects (`AdvancedRateLimiterDO`, `WorkflowExecutorDO`) declared but not actively referenced in request pipeline; SmartCaching implementation exists (`src/cloudflare/performance/SmartCaching.ts`) but is never invoked.
- **Local runtime:** `server-production.js` spins up clustered Node/Express proxy with heavy logging for local parity (`server-production.js:1`).

## Performance & Cold Start
- `initializeServices` logs dozens of emoji messages and instantiates every integration (AI, queue, analytics, Supernova) on the first request, extending cold start well past 150 ms (`src/index.ts:66`). Services should be lazy-initialized per feature flag to lower bundle size and TTFB.
- `nodejs_compat` pulls in the Node polyfill layer, inflating the worker bundle and increasing boot time. Audit dependencies to see if remaining CommonJS modules can be bundled away before removing the flag (`wrangler.toml:4`).
- Request handling races a manual timeout (`RequestPerformanceManager`), but Cloudflare already enforces 50 ms CPU per request. Consider relying on `ctx.waitUntil` for async work instead of `Promise.race` with `setTimeout` to avoid unnecessary 504s (`src/index.ts:302`).
- `SmartCaching` is built but never wired into responses, so every GET hits D1 or KV. Introduce middleware that sets cache hints and reuses `SmartCaching.get`/`set` for hot endpoints (e.g., `/dashboard/stats`, `/crm/leads`) (`src/cloudflare/performance/SmartCaching.ts:28`).

## Data & Cost Efficiency
- D1 bindings (`DB`, `DB_MAIN`, `DB_ANALYTICS`) all point to the same database ID in production and staging; consolidate to single binding to avoid confusion and accidental double billing (`wrangler.toml:23-33`).
- `AuthService` generates `user_*` / `biz_*` IDs with `Date.now()` + random substring, making them guessable at scale; switch to `crypto.randomUUID()` to reduce collision and enumeration risks (`src/modules/auth/service.ts:92-103`).
- Dashboard APIs assume business ID `business-founder-001` when none provided (`src/routes/dashboard/index.tsx:28`, `src/routes/dashboard.ts:20`). Add tenancy guards to prevent cross-account leakage and to fail fast when context headers are missing.
- Many `SELECT` queries lack indices (e.g., filters on `business_id`, `created_at`); define D1 migration scripts that add composite indices to reduce query latency (`database/migrations`).

## Security & Observability
- Token blacklist / rotation modules initialize globally, but revocation relies on KV without TTL enforcement. Ensure `TokenBlacklist.revoke` sets expiry to avoid unbounded key growth (`src/modules/auth/token-blacklist.ts`).
- Observability API exposes `/telemetry/collect` yet writes only to metrics without authentication. Gate with signed tokens or Cloudflare Access headers to prevent abuse (`src/routes/observability.ts:21`).
- Fatal error handler in `index.html` triggers `alert()` for any runtime error, potentially leaking stack traces to end users (`frontend/index.html:93`). Replace with user-friendly error overlays that avoid blocking UI.
- Wrangler observability is enabled with `head_sampling_rate = 0.1`, but no GitHub Action or dashboard ingests the analytics dataset. Use `wrangler tail` and the new latency script to baseline 95th percentile latency.

## Developer Experience
- Multiple worker entrypoints (`index.production.ts`, `index.secure.ts`, etc.) cause ambiguity in local scripts. Document which entry is authoritative and delete stale variants to prevent drift (`src/index.production.ts:1`).
- Local `npm run dev:full` spawns Wrangler and Vite but lacks instructions on required secrets (`package.json:16`). Provide a `.env.example` for frontend + worker, and a short “Getting started” doc for running both layers concurrently.
- Production server script is 575 lines with custom clustering and signal handling (`server-production.js:1`). Consider swapping to Wrangler’s `pages dev` for parity; current script duplicates Cloudflare behaviour poorly and increases maintenance.
- New audit scripts (`scripts/audit/run-axe-audit.mjs`, `scripts/audit/worker-latency.mjs`) expose repeatable checks. Wire them into CI (see “Actionable Steps” below) and publish artifacts (`scripts/audit/README.md:5`).

## Zero-Cost Telemetry Plan
1. **Microsoft Clarity** – inject async script in `frontend/index.html` after consent banner; gate behind `CLARITY_ID` env to toggle per deployment.
2. **Web Vitals** – lazily import `web-vitals` inside `frontend/src/main.tsx` and post metrics to Workers KV or Cloudflare Analytics (free tier).
3. **PageSpeed snapshots** – add GitHub Action invoking `npm run audit:lighthouse` nightly and upload HTML reports (config in `scripts/audit/lighthouserc.json`).
4. **Worker monitoring** – schedule `npm run audit:worker-latency` to run after every deploy and push JSON to `audit-results/latency/` for historical graphs.
5. **Cloudflare Analytics** – use `wrangler tail --metrics=trace` to watch 99th percentile latency during load tests; ensure alerts tie into free email notifications.

## Metrics Dashboard (targets)
| Metric | Target | Notes / Tooling |
| --- | --- | --- |
| LCP (desktop marketing) | `< 2.5 s` | Remove router lazy import, serve hero from Pages cache + `audit:lighthouse`. |
| INP | `< 200 ms` | Trim synchronous logging, preconnect fonts, monitor via `web-vitals`. |
| CLS | `< 0.1` | Lock hero height, avoid async stats injection. |
| Worker p95 latency | `< 150 ms` at edge | Baseline with `audit:worker-latency`; add SmartCaching for dashboard stats. |
| Auth success rate | `> 99%` | Track via `/api/v1/auth/register` instrumentation + Wrangler analytics. |
| Error budget | `< 0.1%` 5xx per week | Use Cloudflare Logs push or Analytics Engine sampling. |

## Actionable Backlog
**P0**
- Lazy-initialize optional services (AI, WebSocket, Supernova) and guard with env flags to cut cold start (`src/index.ts:110`).
- Add caching middleware so `/api/v1/dashboard/stats` and other read-heavy endpoints honour `Cache-Control` + KV caching (`src/routes/dashboard.ts:15`, `src/cloudflare/performance/SmartCaching.ts:196`).
- Replace `Date.now()`-based IDs in auth/finance modules with UUIDs and enforce tenant-aware queries (`src/modules/auth/service.ts:92`).

**P1**
- Consolidate Wrangler bindings: remove duplicate D1 entries, document KV usage, and ensure Durable Objects referenced in code (`wrangler.toml:19-120`).
- Create `.env.example` for both worker and frontend, and document `npm run dev:full` prerequisites in `/docs/development.md`.
- Add GitHub Action workflow: lint → `npm run audit:a11y` → `npm run audit:lighthouse` (upload HTML artifacts) → `npm run audit:worker-latency` (attach JSON).
- Instrument Microsoft Clarity + web-vitals reporting guarded by consent (`frontend/index.html:10`, `frontend/src/main.tsx:90`).

**P2**
- Refactor to a single router (Hono) and remove `itty-router` indirection to simplify handler logic (`src/index.ts:245`).
- Evaluate replacing custom `server-production.js` with Wrangler dev server or Miniflare for closer parity.
- Build KPI dashboards using Cloudflare Analytics dataset instead of bespoke `AnalyticsDashboard` class (reduce maintenance, leverage free tier).
