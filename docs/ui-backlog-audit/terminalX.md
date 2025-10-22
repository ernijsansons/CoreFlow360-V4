# Terminal X — Catalogue Backend Features

Objective: build an authoritative list of backend capabilities that may lack UI exposure.

> Open in **Terminal X** (repo root).

---

## 1. Generate Service Inventory

List modules under `src/modules` (adjust path as needed):

```pwsh
Get-ChildItem src/modules -Directory | Select-Object Name
```

Export to a notes file for PM handoff:

```pwsh
Get-ChildItem src/modules -Directory |
  Select-Object Name |
  ConvertTo-Json |
  Out-File audit/backend-modules.json
```

---

## 2. Identify Public APIs (Handlers/Routes)

Search for route definitions:

```pwsh
rg -n "complianceAdmin\\.post" src/routes
rg -n "app\\.get" src/routes
rg -n "router\\.post" src/
```

Collate results into `audit/backend-routes.md` (append):

```pwsh
rg "router\.(get|post|put|delete)" src -n > audit/backend-routes.md
```

---

## 3. Cross-Reference Service Exports

Find exported functions/classes that look user-facing but lack route usage:

```pwsh
rg "export (async )?function" src/modules -n > audit/backend-exports.txt
```

Greps for unused exports via TypeScript compiler (optional but helpful):

```pwsh
npx ts-unused-exports tsconfig.json > audit/unused-exports.txt
```

---

## 4. Tag Features Likely Missing UI

For each module (e.g. `finance`, `compliance`, `agents`), jot a quick summary in `audit/backend-feature-matrix.md`:

```md
## Compliance
- APIs: POST /guidelines, GET /violations, …
- Dependencies: DB tables company_guidelines, agent_policies
- UI coverage: TBD (check Terminal Y)

## Finance
- Services: InvoiceManager.mapToInvoice, …
- UI exposure: ??? (Terminal Y)
```

Use `apply_patch` to keep the file tidy.

---

## 5. Produce DB Schema Snapshot (Optional)

If using Prisma/Drizzle/etc., capture schema to help UI mapping:

```pwsh
Get-Content prisma/schema.prisma > audit/schema.snapshot
```

---

## 6. Hand-off

Ensure `audit` directory contains:
* `backend-modules.json`
* `backend-routes.md`
* `backend-feature-matrix.md`
* `unused-exports.txt` (optional)

Proceed to Terminal Y with `docs/ui-backlog-audit/terminalY.md`.

