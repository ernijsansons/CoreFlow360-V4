# Terminal B — Staging Deployment & Smoke Checks

Objective: deploy the release candidate to staging, verify key workflows, and capture evidence.

> Open in **Terminal B** (fresh shell).  
> Ensure Terminal A completed successfully.

---

## 1. Login to Staging Infrastructure

If using a deployment CLI (adjust as needed):

```pwsh
az login --tenant <tenant-id>    # or aws/gcloud login
az account set --subscription <staging-subscription>
```

For SSH-based deploys:

```pwsh
ssh deployer@staging.example.com
```

---

## 2. Push Artifacts to Staging

**Option A: CI Trigger**

```pwsh
gh workflow run deploy-staging.yml --ref <tag-from-terminalA>
```

Monitor workflow status:

```pwsh
gh run watch
```

**Option B: Manual**

```pwsh
scp artifacts/app.zip deployer@staging.example.com:/srv/releases/
ssh deployer@staging.example.com "unzip -o /srv/releases/app.zip -d /srv/app && sudo systemctl restart app-staging"
```

---

## 3. Run Database Migrations (If Required)

```pwsh
ssh deployer@staging.example.com "cd /srv/app && npm run migrate:staging"
```

Confirm success before continuing.

---

## 4. Smoke Test Staging

Automated:

```pwsh
npx vitest run --config vitest.staging.config.ts
```

Manual checklist (record results):

1. Login flow works (user + admin).
2. Compliance admin routes respond with HTTP 200 for positive cases.
3. Recent API gateway changes log slow requests appropriately (`tail -f` staging logs).
4. Invoice manager screens load without console errors.

Capture screenshots or log snippets for release notes.

---

## 5. Approve for Production

If staging passes, mark the release as “ready” in your tracker (Jira/Notion).  
Notify stakeholders in the deployment channel.

---

## 6. Hand-off

Leave Terminal B with CLI output for auditing.  
Proceed to Terminal C and open `docs/deploy-handbook/terminalC.md`.

