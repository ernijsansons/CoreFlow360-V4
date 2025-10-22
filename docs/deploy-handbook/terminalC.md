# Terminal C — Production Deployment & Post-Checks

Goal: promote the approved build to production, monitor rollout, and close the deployment loop.

> Open in **Terminal C** after Terminal B completes.  
> Use elevated privileges where necessary.

---

## 1. Production Access

Authenticate with production credentials:

```pwsh
az account set --subscription <production-subscription>
# or
ssh deployer@prod.example.com
```

Confirm you are in the correct environment before proceeding.

---

## 2. Deploy Release Candidate

**CI-Based Deployment**

```pwsh
gh workflow run deploy-prod.yml --ref <tag-from-terminalA>
gh run watch
```

Ensure the workflow includes approval gates. Provide sign-off when prompted.

**Manual Deployment**

```pwsh
scp artifacts/app.zip deployer@prod.example.com:/srv/releases/
ssh deployer@prod.example.com "
  set -e
  unzip -o /srv/releases/app.zip -d /srv/app &&
  npm run migrate:prod &&
  sudo systemctl restart app-prod
"
```

---

## 3. Verify Production Health

### Automated Smoke Tests

```pwsh
npm run smoke:prod   # replace with actual command
```

### Monitoring

* Check dashboards (APM, logs, uptime).  
  Example:

  ```pwsh
  az monitor metrics list --resource <app-service> --metric Requests,ServerErrors --interval 5m
  ```

* Tail logs for critical services:

  ```pwsh
  ssh deployer@prod.example.com "journalctl -u app-prod -f --since '10 minutes ago'"
  ```

### Manual Sanity

1. Login as an admin; execute a compliance guideline update.
2. Create invoices via UI/API to verify mapper changes.
3. Confirm API gateway slow-query alerts only trigger above threshold.

Document each check (screenshot or note).

---

## 4. Rollback Plan (Standby)

If any issue arises:

```pwsh
ssh deployer@prod.example.com "
  sudo systemctl stop app-prod &&
  cp -r /srv/backups/app-<last-good-tag>/* /srv/app/ &&
  sudo systemctl start app-prod
"
```

Notify incident channel immediately and begin triage.

---

## 5. Finalise Deployment

* Update release notes with:
  * Deployment window (start/end).
  * Monitoring summary (metrics, alerts).
  * Outstanding follow-ups (if any).
* Close the tracking ticket (Jira/Notion).
* Announce completion in the team channel with key highlights.

---

## 6. Archive Artefacts

Move local artifacts to long-term storage if policy requires it:

```pwsh
Move-Item artifacts\* \\fileserver\deploy-archives\YYYY\MM\
```

Clean up local build output:

```pwsh
Remove-Item artifacts -Recurse -Force
```

---

## 7. Close Out

```pwsh
git status -sb
```

Should remain clean (no production secrets or artifacts).  
Shutdown Terminals A, B, C after documenting outcomes.

