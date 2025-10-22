# Terminal A — Pre-Deploy Validation & Artifact Prep

Goal: confirm the repo is ready, freeze versions, and produce deployable artifacts.

> Open this file in **Terminal A** (repo root).  
> All shell commands use `pwsh`.

---

## 1. Confirm Clean Working Tree

```pwsh
git status -sb
```

*Must show “working tree clean”. Resolve outstanding changes before proceeding.*

---

## 2. Pin Build Metadata

Update the release notes with deployment metadata (version/date/commit). Suggested file: `docs/release-notes/next.md`. Use `apply_patch` to append:

```md
## Deployment YYYY-MM-DD
- Commit: `<git rev-parse --short HEAD>`
- Environment: staging ➜ production
- Summary: …
```

---

## 3. Final Build Verification

```pwsh
npm run build
```

If the build emits artifacts (e.g. `dist/`), verify contents:

```pwsh
Get-ChildItem dist -Recurse | Select-Object -First 20
```

Archive the build (optional but recommended):

```pwsh
Compress-Archive -Path dist\* -DestinationPath artifacts\app.zip -Force
```

---

## 4. Tag the Release Candidate

```pwsh
$commit = git rev-parse HEAD
$tag = "prepare/" + (Get-Date -Format 'yyyyMMdd-HHmmss')
git tag $tag $commit
git push origin $tag
```

Document the tag in release notes.

---

## 5. Export Environment Config Snapshot

If your deployment uses `.env` files or secrets, capture the staging/prod diff:

```pwsh
Get-Content .env.staging > artifacts/env.staging.snapshot
Get-Content .env.production > artifacts/env.production.snapshot
```

Ensure secret files remain secure (do not commit snapshots; they live in `artifacts/` for operator reference).

---

## 6. Hand-off

Leave Terminal A open with build and tag confirmation.  
Move to Terminal B and open `docs/deploy-handbook/terminalB.md`.

