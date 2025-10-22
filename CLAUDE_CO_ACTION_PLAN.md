# CoreFlow360 Frontend – Claude Co Action Plan

This document guides the next Claude Co agent through a complete investigation and remediation of the production crash. Follow the steps meticulously; do not skip ahead. Capture every artifact requested.

---

## 1. Current Failure Snapshot

**Symptom in production preview**
- Page shows loading screen briefly, then the TanStack Router error boundary.
- Browser console (screenshot supplied) reports:
  ```
  react-dom.production.min.js:188 TypeError: Cannot read properties of null (reading 'useEffect')
      at react_production.useEffect (react.production.js:503:21)
      at QueryClientProvider (QueryClientProvider.js:23:3)
      … (React stack truncated)
  error-boundary.tsx:32 ErrorBoundary caught an error: TypeError: Cannot read properties of null (reading 'useEffect')
  ```

**Key implications**
- The crash fires when `<QueryClientProvider>` renders.
- `ReactCurrentDispatcher.current` is `null`, meaning React hooks aren’t properly initialised for that component—typically caused by a broken React/React Query install or double-bundled React.

Your mission is to prove the exact cause and land a permanent fix.

---

## 2. Reproduce Locally

1. `cd frontend`
2. Install dependencies (`npm install`) to ensure a clean node_modules.
3. `npm run preview`
4. Visit the preview URL (usually `http://localhost:4173`). Confirm the same crash occurs.  
   - Leave the console open and capture a screenshot showing the stack trace.
   - Copy the top of the stack trace to `notes/query-provider-error.txt`.

---

## 3. Dependency Integrity Checks

Run the following diagnostics from `frontend/` and paste results into `notes/dependency-audit.txt`:

```bash
npm ls react
npm ls react-dom
npm ls @tanstack/react-query
npm ls @tanstack/query-core
npm ls typescript
```

Interpretation guidelines:
- `react` and `react-dom` must resolve to exactly one version (`18.3.1`).
- `@tanstack/react-query` **must be present**. `npm ls` currently returns `(empty)`—confirm whether the package is actually missing or installed via some indirect mechanism. If missing, this is a smoking gun.
- `@tanstack/query-core` version should align with `@tanstack/react-query`.

If any package is missing or duplicated, document it explicitly in `notes/dependency-audit.txt`.

---

## 4. File System Verification

We suspect `@tanstack/react-query` is not physically installed. Verify and document the outcome:

```bash
dir node_modules\@tanstack
dir node_modules\@tanstack\react-query
dir ..\node_modules\@tanstack
dir ..\node_modules\@tanstack\react-query
```

If the directory is missing, note the absence. If it exists, record the exact path and version files (`package.json`) in `notes/dependency-audit.txt`.

---

## 5. Inspect Bundled Output

Confirm whether the build is bundling a React Query implementation from an unexpected location (e.g., cached micro-frontend artifacts):

1. `npm run build`
2. Search `frontend/dist` for references to `QueryClientProvider`:
   ```bash
   rg "QueryClientProvider" dist -n
   ```
3. If found, note the containing file path in `notes/bundle-analysis.txt`.  
   - If not found, the bundle may be tree-shaking React Query entirely (which would be suspicious given all the imports).
4. Additionally, inspect `.vite` caches if needed:
   ```bash
   rg "QueryClientProvider" node_modules/.vite** -n
   ```
   (Use globbing carefully; document any hits.)

---

## 6. Root Cause Hypotheses to Validate

Test each possibility systematically. Record findings in `notes/hypothesis-testing.txt`.

### H1. **Missing or stale `@tanstack/react-query`**
- If `npm ls @tanstack/react-query` is empty, install a compatible version:
  ```bash
  npm install @tanstack/react-query@5.51.25
  ```
- Repeat the build + preview. If the crash disappears, this was the root cause.

### H2. **Duplicate React bundles**
- After reinstalling, re-run `npm ls react` to ensure only one version (18.3.x) is present.
- Check `frontend/vite.config.ts` for aliases that might pull in another React build. Document any suspicious aliases.

### H3. **Hook misuse inside our provider**
- Open `frontend/src/providers/query-provider.tsx` (already recorded). This file is straightforward—it shouldn’t trigger the issue. Cross-verify that `QueryProvider` is only used via JSX (`<QueryProvider>`), not called as a plain function anywhere else:
  ```bash
  rg "QueryProvider(" src -g '*.tsx'
  ```
  Ensure occurrences are JSX tags (`<QueryProvider`) rather than `QueryProvider(` invocation.

### H4. **Lazy router import side-effects**
- Confirm that `frontend/src/App.tsx` does not import `QueryClientProvider` before React is initialised. The lazy `import('./router')` should be harmless, but double-check that no synchronous code path executes React Query outside React.

Document the outcome of each hypothesis (pass/fail, evidence) in the notes file.

---

## 7. Implement the Fix

Depending on the diagnostic outcome:

1. **If React Query was missing:**  
   - Add `@tanstack/react-query` to `dependencies` in `frontend/package.json`.  
   - Run `npm install`.  
   - Commit lockfile changes after validation.
2. **If version mismatch:**  
   - Align `@tanstack/query-core` and `@tanstack/react-query` to matching versions (latest 5.x).  
   - Re-run installs and builds.
3. **If duplicate React:**  
   - Resolve by enforcing alias in `vite.config.ts` (e.g., alias `'react'` and `'react-dom'` to the project root versions).  
   - Remove any conflicting bundler configuration.
4. **If internal misuse found:**  
   - Refactor the offending component/hook usage so that React hooks execute only within React render.  
   - Add unit tests if feasible (React Testing Library or Vitest) to assert that `<App />` renders without throwing.

Ensure code changes are minimal and well-commented where necessary.

---

## 8. Validation

1. `npm run lint`
2. `npm run typecheck`
3. `npm run test` (or targeted suites involving hooks/API).
4. `npm run build`
5. `npm run preview` and manually confirm the app loads, routes render, and the router error boundary no longer appears.
6. Run the production build locally with `npx serve dist` (or similar) to mimic Cloudflare Pages if needed.

Record evidence (screenshots, command outputs) in `notes/validation.txt`.

---

## 9. Production Deployment Readiness

1. Remove any temporary diagnostics (e.g., `window.__CF360_FATAL__` alerts) after confirming the fix.  
   - If the fatal dump script is still required, downgrade it to console logging rather than blocking alerts.
2. Update `PRODUCTION_RECOVERY_EXECUTION_PLAN.md` with the actual root cause and resolution summary.
3. Prepare a deployment checklist itemising:
   - `npm run build`
   - Cloudflare deployment command used
   - Post-deploy smoke tests (list each route checked)

Document all of this in `notes/deployment-plan.txt`.

---

## 10. Final Deliverables

When the fix is ready:

1. Summarise the root cause, fix, and validations in `LLM_HANDOFF_PRODUCTION_CRISIS.md` under a new “Resolution” section.
2. Provide a short TODO list for long-term hardening (e.g., add e2e test ensuring `<App>` + router + QueryClientProvider render).
3. Indicate whether `@tanstack/react-query` should remain as an explicit dependency going forward (almost certainly yes).

Only hand back when:
- All notes files are populated.
- App runs without the QueryClientProvider crash in both preview and production builds.
- Documentation has been updated so future engineers understand what went wrong and how it was fixed.

---

## Appendix – Useful Commands

```bash
# Clean install
rm -rf node_modules package-lock.json
npm install

# Focused React Query test
npm test -- QueryProvider

# Serve build locally
npx http-server dist
```

If at any point you discover a different root cause than documented here, update this plan before proceeding so the handoff remains accurate. Leave nothing ambiguous.*** End Patch
