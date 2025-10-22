# Terminal 2 — Full Verification Pass

Objective: certify the repo after Terminal 1’s fixes. This terminal runs the heavyweight checks (tests, lint, type-check) and captures artefacts needed for sign-off.

> Open this file in **Terminal 2**.  
> Start in the repository root.

---

## 1. Update Dependencies (If Needed)

We normally skip install for speed. Only run the following if `npm install` hasn’t been executed on this machine today or if package.json changed:

```pwsh
npm install
```

Otherwise continue.

---

## 2. Warm the Vitest Cache

```pwsh
npx vitest run --passWithNoTests
```

This primes transform caches so the full suite below runs faster.

---

## 3. Full Test Suite

```pwsh
npx vitest run
```

*Expected runtime ~8–10 s with warm cache.*  
If anything fails, collect the first failure details, loop back to Terminal 1 (or branch off) to address them, then rerun until green.

---

## 4. Lint & Formatting

```pwsh
npm run lint
```

If the repo has format scripts, run them as well:

```pwsh
npm run format -- --check
```

Fix any findings before proceeding.

---

## 5. Type Checking

```pwsh
npm run type-check
```

Capture any errors; they must be resolved before shipping.

---

## 6. Smoke Build (Optional but Recommended)

If the project ships a production bundle:

```pwsh
npm run build
```

Abort on failure and report upstream.

---

## 7. Summarise Verification

Record command outputs (last few lines) for the final report. Example snippet to grab the vitest summary:

```pwsh
npx vitest run --reporter=json > .tmp/vitest-summary.json
Get-Content .tmp/vitest-summary.json
```

Delete `.tmp` afterwards if created.

---

## 8. Hand-off

Leave Terminal 2 with the successful command outputs visible.  
Switch to Terminal 3 and open `docs/ship-plan/terminal3.md`.

