# CoreFlow360 Audit Scripts

Automation helpers for repeatable UX and DX checks. All tools run locally with free OSS dependencies.

## Prerequisites

- `npm install` at the repository root (installs Playwright, Lighthouse, etc.).
- The marketing app running on `http://localhost:3000` (`npm run dev --prefix frontend`) for front-end checks.
- The Worker running on `http://127.0.0.1:8787` (`npm run dev:watch`) for latency sampling.

Override defaults via environment variables shown below.

## Available scripts

| Command | Description | Environment variables |
| --- | --- | --- |
| `npm run audit:a11y` | Launches headless Chromium + axe-core to scan public pages for WCAG 2.1 A/AA violations. Fails the run if violations exist. | `CF360_BASE_URL` (default `http://localhost:5173`) |
| `npm run audit:lighthouse` | Executes Lighthouse CI across the primary marketing routes with stricter performance / a11y budgets. Stores HTML/JSON reports in `audit-results/lighthouse/`. | none |
| `npm run audit:worker-latency` | Samples Worker latency for `/health`, `/api/v1/observability/health`, and `/api/v1/dashboard/stats`. Records average, p95, and status distribution. | `CF360_WORKER_BASE_URL`, `CF360_LATENCY_ITERATIONS`, `CF360_AUDIT_OUTPUT` |

## Suggested CI wiring

- Add a nightly GitHub Action that runs `npm run audit:lighthouse` to track regressions.
- Gate PRs by running `npm run audit:a11y` on marketing changes.
- Schedule `npm run audit:worker-latency` after deployments and publish the JSON to the `audit-results/` artifact for historic baselines.
