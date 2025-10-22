# Terminal Z — Integration Plan & Acceptance Tests

Objective: convert the audit findings into actionable integration tasks, acceptance criteria, and tracking artifacts.

> Open in **Terminal Z** after Terminal Y completes.

---

## 1. Consolidate Gaps

Combine notes into a single `audit/backlog-summary.md`:

```pwsh
"# Backend↔UI Backlog Summary`n" |
  Out-File audit/backlog-summary.md -Encoding UTF8
Get-Content audit/backend-feature-matrix.md >> audit/backlog-summary.md
Get-Content audit/ui-gaps.md >> audit/backlog-summary.md
```

Review and tidy the markdown manually (use `apply_patch`).

---

## 2. Define User Stories / Tickets

For each ❌ or ⚠️ entry, create a story stub in `audit/user-stories.md`:

```md
## Story: Surface Compliance Guidelines in UI
- Backend APIs: POST/GET /api/v1/admin/compliance/guidelines
- Required UI: Admin Dashboard > Compliance tab
- Acceptance Criteria:
  1. Admin can create/edit guidelines with validation.
  2. List view pulls from backend (pagination).
  3. Errors display within 2s.
- Dependencies: design assets, feature flag `complianceAdmin`.
```

Repeat for each missing feature (policies, violations, finance etc.).

---

## 3. Outline Acceptance Tests

Create `audit/e2e-test-plan.md` with sections:

```md
## Compliance Admin (new)
- Scenario: Create guideline -> appear in list.
- API: POST /guidelines, GET /guidelines
- UI Path: /admin/compliance
- Tools: Playwright/Vitest + staging seed data

## Invoice Enhancements
- Scenario: Load invoice with new metadata fields → verify UI renders normalized data.
```

Add steps for logging/alerts as needed.

---

## 4. Link to Tracking System

If using Jira/Linear:

```pwsh
Get-Content audit/user-stories.md |
  gh issue create --title "UI Integration: Compliance Admin" --body - # repeat manually per story
```

Alternatively annotate each story with “Ticket: TBD” for PM to fill in.

---

## 5. Communicate Findings

Summarise the audit in `docs/release-notes/next.md` or a dedicated `docs/ui-backlog-report.md`:

* Number of backend features lacking UI.
* Highest priority gaps.
* Proposed timeline (e.g., “Sprint 34: compliance admin UI”).

---

## 6. Archive

Ensure `audit/` folder is committed (unless it contains sensitive data).  
If large, compress and upload to internal knowledge base.

---

## 7. Close Audit

* Review all three terminal outputs.
* Share `audit/backlog-summary.md` with PM/design.
* Create follow-up tickets before leaving the branch.

