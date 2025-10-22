# Terminal Y — Trace UI Coverage & Identify Gaps

Goal: map the backend inventory (Terminal X) to actual UI surfaces, highlighting missing connections.

> Open in **Terminal Y** (clean shell).  
> Ensure Terminal X artifacts exist in `audit/`.

---

## 1. Enumerate UI Entry Points

List major front-end directories (adjust path):

```pwsh
Get-ChildItem src/ui -Directory | Select-Object Name
```

Capture to `audit/ui-modules.json`:

```pwsh
Get-ChildItem src/ui -Directory |
  Select-Object Name |
  ConvertTo-Json |
  Out-File audit/ui-modules.json
```

---

## 2. Grep for API Usage

Search UI code for fetch/axios/graphql calls referencing backend routes:

```pwsh
rg "/api/v1" src/ui -n > audit/ui-api-usage.txt
rg "compliance" src/ui -n >> audit/ui-api-usage.txt
rg "invoice" src/ui -n >> audit/ui-api-usage.txt
```

Mark modules with **no** API hits; add to a “missing coverage” section.

---

## 3. Component Inventory vs Backend Matrix

Open `audit/backend-feature-matrix.md` and annotate each section with UI findings.  
Example (edit via `apply_patch`):

```md
## Compliance
- APIs: …
- UI coverage: ❌ no hits in `src/ui/compliance/`
- Notes: create admin screens for guidelines & policies.
```

Use ✅ for covered, ⚠️ for partial, ❌ for missing.

---

## 4. Trace State Management / Hooks

Identify reusable hooks or stores:

```pwsh
rg "useCompliance" src/ui -n
rg "useInvoice" src/ui -n
```

If backend features lack corresponding hooks, note them in `audit/ui-gaps.md`:

```md
- Missing hook: `useGuidelines` (backend has POST/GET guidelines)
- Missing hook: `useAgentPolicies`
```

---

## 5. Review Navigation & Permissions

Check route configuration (React Router, Next.js pages, etc.):

```pwsh
rg "<Route" src/ui -n > audit/ui-routes.txt
```

Ensure new backend segments are reachable from UI. Highlight missing nav entries in `audit/ui-gaps.md`.

---

## 6. Collect UX/Design Debt

Create `audit/ui-design-notes.md` summarising:

* Screens needed (e.g. “Compliance Admin Dashboard”).
* Components to reuse or extend.
* Permissions/feature flags required.

Get UX sign-off later.

---

## 7. Hand-off

Verify `audit/` now includes:
* `ui-modules.json`
* `ui-api-usage.txt`
* `ui-gaps.md`
* Updated `backend-feature-matrix.md`

Proceed to Terminal Z with `docs/ui-backlog-audit/terminalZ.md`.

