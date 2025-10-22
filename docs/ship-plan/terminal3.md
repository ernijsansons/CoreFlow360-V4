# Terminal 3 — Release Prep & Documentation

Purpose: once Terminals 1 & 2 succeed, use this terminal to wrap the work, document outcomes, and prepare for merge/release.

> Open this file in **Terminal 3** (repo root).

---

## 1. Snapshot Workspace State

```pwsh
git status -sb
```

Take note of modified files (should match the expected set from Terminals 1 & 2).

---

## 2. Capture Test & Lint Artefacts

From Terminal 2 you should already have passing logs. If you need them again:

```pwsh
npx vitest run --reporter=dot
npm run lint
npm run type-check
```

Export key snippets to attach to the release notes (copy/paste is fine).

---

## 3. Update Documentation / Roadmap

Add a short entry describing the completed work. Suggested file: `docs/eslint-warning-burndown-roadmap.md` (existing). Append under the latest date:

* Summary of compliance admin hardening.
* Note that CRM DB + Invoice Manager tests now cover normalised rows.
* Mention that API gateway slow-path logging is in place.

Use `apply_patch` to keep the diff tight.

---

## 4. Prepare Commit (Optional if ship via PR)

If the workflow requires local commit:

```pwsh
git add src/__tests__/api/gateway/api-gateway.test.ts `
         src/__tests__/database/crm-database.test.ts `
         src/__tests__/modules/finance/invoice-manager.test.ts `
         src/api/gateway/api-gateway.ts `
         src/modules/finance/invoice-manager.ts `
         docs/ship-plan/*.md

git commit -m "Finalize compliance admin rollup and verification"
```

Skip commit if policy is to leave it for PR author; just ensure staging matches the expected files and capture the proposed commit message.

---

## 5. Draft Merge / Release Notes

Create or update `docs/release-notes/next.md` (or location of your choice) with:

* **Highlights** – compliance admin API fixes, invoice mapper normalization, API gateway slow logging.
* **Verification** – vitest, lint, type-check results.
* **Follow-ups** – anything still pending (e.g. further integration tests).

---

## 6. Final Sanity Check

```pwsh
git status -sb
```

Confirm nothing unexpected remains. If clean, you’re ready to hand this off for review/merge.

---

## 7. Close Out

* Post the command outputs and diff summary in the shared channel (or include in PR description).
* Archive Terminals 1 & 2 outputs if required by the team.

Done—ship it! 🚢

