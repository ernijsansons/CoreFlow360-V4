# CoreFlow360 V4 Production Recovery Plan

This playbook documents the end‑to‑end steps required to capture the hidden production failure, implement the corrective fix, and return `https://production.coreflow360-frontend.pages.dev` to a healthy state. Follow each phase in order—do not skip ahead.

---

## Phase 0 – Preconditions

1. **Environment**
   - You have terminal access to the CoreFlow360 V4 repository on the workstation that produced the current deployment.
   - Node.js ≥ 20.0.0 is installed (check with `node --version`).
   - `npm install` has been run both at repo root and in `frontend/` (only repeat if dependencies changed).
2. **Branch Hygiene**
   - Ensure you are on the intended working branch (`git status` should show clean or only purposeful changes).
   - DO NOT commit or push until the fix is validated locally.

---

## Phase 1 – Capture the Crash Signature

1. **Rebuild the Frontend**
   - `cd frontend`
   - `npm run build`
   - Wait for a successful build (Vite summary should conclude with `✓ built`).
2. **Deploy to Cloudflare Pages Preview**
   - Use the existing deployment mechanism (e.g., `npm run deploy:prod` or Cloudflare Pages Git commit trigger).
   - If using a manual upload, ensure `frontend/dist/` is the artifact.
3. **Load the Broken URL**
   - While the preview or production deployment finishes, prepare an incognito/private browser session.
   - Navigate to `https://production.coreflow360-frontend.pages.dev` once the deployment completes.
4. **Capture the Fatal Dump**
   - When the TanStack Router error boundary appears, an alert should fire. Copy its full text to a clipboard-safe document.
   - Scroll to the top of the DOM: a red `<pre>` block with id `cf360-fatal-dump` will be pinned. Click inside, `Ctrl+A`, `Ctrl+C`.
   - Paste the contents into a local scratch file named `fatal-dump.txt` for later reference.
5. **Cross-Check Router Details Panel**
   - Expand the `<details>` element rendered inside the boundary.
   - Confirm whether the message mirrors the alert; if it differs, copy both outputs.
6. **Log Evidence**
   - Save browser console output (even if empty) and Network tab screenshots showing all scripts downloaded successfully.

---

## Phase 2 – Diagnose the Root Cause

1. **Inspect `fatal-dump.txt`**
   - Identify the first stack frame that references project code (e.g., `frontend/src/routes/...` or `frontend/src/providers/...`).
   - Note the error type, message, and file path.
2. **Trace Module Initialization**
   - Open the implicated file in the repository.
   - Look for code that runs at module scope or inside React components/providers executed during initial navigation:
     - Synchronous `throw` statements.
     - Direct `window` / `document` usage without guards.
     - Top-level awaits, API calls, or environment assumptions.
3. **Validate Assumptions**
   - If the error hints at missing data (e.g., `undefined` property access), confirm via TypeScript definitions or API contracts.
   - If it references browser globals, reproduce by running `npm run preview` and loading the same route locally to observe console output.
4. **Document the Hypothesis**
   - Record in `fatal-dump.txt` (or a new note) a concise hypothesis: “Module X throws because Y.”

---

## Phase 3 – Implement the Fix

1. **Code Change**
   - Modify only the implicated module(s) to eliminate the failing assumption (e.g., add guards, lazy-load browser-only logic, adjust provider wiring).
   - Keep the fix minimal but comprehensive—cover all code paths matching the failure signature.
2. **Regression Protection**
   - Add or update a unit/integration test demonstrating the scenario that previously failed (preferably rendering the route/provider using React Testing Library or Vitest).
   - Ensure the test fails before the fix and passes after.
3. **Remove Temporary Instrumentation**
   - Delete the production-only error surface block from `frontend/src/main.tsx` once confident the root cause is resolved.
   - Re-run `npm run lint`, `npm run typecheck`, and relevant tests to confirm no regressions.

---

## Phase 4 – Validate Locally

1. **Local Preview**
   - `cd frontend`
   - `npm run preview`
   - Visit `http://localhost:4173` (or the port shown) and navigate through:
     - Landing page
     - Auth routes
     - Any dashboard route referenced in the fatal stack trace
   - Confirm no error boundary appears; watch the browser console for warnings.
2. **Vitest/ESLint Verification**
   - Execute `npm run test` (or the specific suite relevant to the change).
   - Execute `npm run lint` to enforce lint rules.

---

## Phase 5 – Deploy & Smoke Test

1. **Production Build**
   - `cd frontend`
   - `npm run build`
   - Verify build succeeds without warnings related to the touched modules.
2. **Deploy**
   - Promote the build to Cloudflare Pages production (via CLI or CI).
3. **Smoke Test in Production**
   - In an incognito window, hit `https://production.coreflow360-frontend.pages.dev`.
   - Walk through the same navigation path as in local preview.
   - Confirm routers and providers load, the loading screen disappears, and no error boundary renders.
4. **Monitor**
   - Watch browser console and Network tab for anomalies.
   - Optionally verify Cloudflare logs or monitoring dashboards for new errors.

---

## Phase 6 – Communicate & Close Out

1. **Summarize the Incident**
   - In `LLM_HANDOFF_PRODUCTION_CRISIS.md` (or a new postmortem section), document:
     - Root cause summary.
     - Fix implemented.
     - Tests added.
     - Deployment timestamp.
2. **Stakeholder Update**
   - Notify the user/stakeholder that production is restored, referencing the summary.
3. **Backlog Hardening (Optional)**
   - Propose long-term safeguards: e.g., re-enable Sentry logging, require production smoke tests in CI/CD, add e2e coverage for initial navigation.

---

## Quick Reference Checklist

| Phase | Task | Status (✓/✗) |
| ----- | ---- | ------------- |
| 0 | Environment ready, branch clean | |
| 1 | Fatal dump captured | |
| 2 | Root cause identified | |
| 3 | Fix implemented + tests | |
| 4 | Local validation passed | |
| 5 | Production deployed & smoke-tested | |
| 6 | Communication completed | |

Mark each item as you progress to ensure nothing is missed.

---

**Reminder:** Do not remove the `cf360-fatal-dump` instrumentation until after you have the stack trace and are confident in the fix. Removing it too early will reintroduce silent failures if another regression exists.
