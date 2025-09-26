# Repository Map - CoreFlow360 V4
## Cloudflare Workers/Pages Application Structure

**Generated:** 2025-09-26
**Total Size:** 142.41 MB (excluding .git & node_modules)
**File Count:** 1,852 files

---

## Directory Tree Overview

```
CoreFlow360 V4/
├── src/                    [7.47 MB] ⭐ Core application code
│   ├── api/                         API gateway and routes
│   ├── cloudflare/                  Cloudflare-specific code
│   │   ├── durable-objects/         Durable Objects classes
│   │   ├── workers/                 Worker handlers
│   │   └── types/                   TypeScript definitions
│   ├── database/                    Database layer
│   ├── middleware/                  Express/Hono middleware
│   ├── modules/                     Business logic modules
│   │   ├── abac/                    Access control
│   │   ├── agent-system/            AI agent system
│   │   ├── agents/                  Agent implementations
│   │   ├── auth/                    Authentication
│   │   ├── business-context/        Business logic
│   │   ├── finance/                 Financial module
│   │   └── workflow/                Workflow engine
│   ├── services/                    Service layer
│   ├── shared/                      Shared utilities
│   ├── types/                       TypeScript types
│   ├── workers/                     Worker scripts
│   ├── index.ts                     Main entry point
│   └── index.minimal.ts             ⭐ Active entry (wrangler.toml)
│
├── frontend/               [3.08 MB] Frontend application
│   ├── src/                         React/Vue source
│   ├── dist/                [1.8 MB] ❌ Build artifacts (REMOVE)
│   └── package-lock.json
│
├── design-system/          [3.65 MB] Design system
│   ├── dist/                [1.5 MB] ❌ Build artifacts (REMOVE)
│   ├── design-tokens.json           Active design tokens
│   └── *.backup-*            [900 KB] ❌ Redundant backups (REMOVE)
│
├── database/               [100 KB]  Database schemas
│   ├── migrations/                   D1 migrations
│   └── schemas/                      Schema definitions
│
├── scripts/                [212 KB]  Build & deployment scripts
│   ├── repo_size_audit.ps1          Size audit script
│   └── [various].mjs                 Token/design scripts
│
├── tests/                  [295 KB]  Test suites
│   ├── integration/                  Integration tests
│   ├── security/                     Security tests
│   ├── performance/                  Performance tests
│   └── tokens/                       Token tests
│
├── .github/                [109 KB]  GitHub Actions
│   └── workflows/                    CI/CD pipelines
│
├── .venv/                  [10.55 MB] ❌ Python virtual env (REMOVE)
├── audit-reports/          [9.15 MB]  ❌ Large JSON reports (REMOVE)
├── coverage/               [227 KB]   ❌ Coverage reports (REMOVE)
├── .wrangler/              [708 KB]   ❌ Wrangler cache (REMOVE)
│
├── PowerShell-*.msi        [104.14 MB] ❌ Installer file (REMOVE)
├── wrangler.toml           [4 KB]    ⭐ Cloudflare config
├── package.json            [8 KB]    ⭐ Project config
├── tsconfig.json           [2 KB]    ⭐ TypeScript config
├── Dockerfile              [3 KB]    Docker config
├── README.md               [5 KB]    Documentation
├── [test-*.js]             [57 KB]   ❌ Misplaced tests (REMOVE)
├── [server-*.js]           [47 KB]   ❌ Dev helpers (REMOVE)
└── [*.log, *.txt]          [1.1 MB]  ❌ Temp files (REMOVE)
```

---

## Cloudflare Entry Points & Dependencies

### Primary Entry Point
```
wrangler.toml → main = "src/index.minimal.ts"
```

### Dependency Chain from Entry
```
src/index.minimal.ts
├── @cloudflare/ai
├── hono (web framework)
├── src/middleware/
│   ├── auth.ts
│   ├── rate-limit.ts
│   └── security.ts
├── src/routes/
│   ├── auth.ts
│   └── index.ts
├── src/database/
│   └── crm-database.ts (D1)
└── src/services/
    └── [various services]
```

### Cloudflare Bindings (from wrangler.toml)
- **D1 Databases:**
  - DB → coreflow360-agents
  - DB_MAIN → coreflow360-agents
  - DB_ANALYTICS → mustbeviral-db

- **KV Namespaces:**
  - KV_CACHE
  - KV_SESSION
  - KV_RATE_LIMIT_METRICS

- **R2 Buckets:**
  - R2_DOCUMENTS → coreflow360-documents
  - R2_BACKUPS → coreflow360-backups

- **Durable Objects:**
  - RATE_LIMITER_DO → AdvancedRateLimiterDO

- **AI Binding:**
  - AI → Cloudflare AI

---

## Build & Deploy Pipeline

### Package.json Key Scripts
```javascript
"dev": "wrangler dev --config wrangler.development.toml"
"build": "tsc && npm run bundle"
"bundle": "esbuild src/index.ts --bundle --outfile=dist/worker.js"
"deploy:prod": "wrangler deploy --config wrangler.production.toml"
"test": "vitest"
```

### CI/CD Workflows (.github/workflows/)
1. **ci.yml** - Continuous integration
2. **deployment.yml** - Production deployment
3. **security-scan.yml** - Security checks
4. **performance-ci.yml** - Performance testing
5. **rollback.yml** - Rollback procedures

---

## Module Architecture

### Core Modules (src/modules/)
```
abac/               - Attribute-based access control
agent-system/       - AI agent orchestration
auth/               - Authentication & JWT
business-context/   - Business logic layer
finance/            - Payment processing (Stripe/PayPal)
workflow/           - Workflow orchestration engine
```

### Service Layer (src/services/)
```
crm-analytics.ts    - Analytics service
workflow-orchestration-engine.ts
revenue-forecast.ts
call-summarizer.ts
```

### Middleware Stack (src/middleware/)
```
1. security.ts      - Security headers, CORS
2. auth.ts          - JWT verification
3. rate-limit.ts    - Rate limiting
4. error-handling.ts - Error handling
```

---

## Asset & Resource Analysis

### Static Assets
- **Frontend Assets:** frontend/src/stories/assets/ (716 KB)
  - Images: addon-library.png, testing.png, theming.png
  - Should remain in repo for Storybook

### Generated Files (Should be gitignored)
- design-system/dist/ (1.5 MB)
- frontend/dist/ (1.8 MB)
- coverage/ (227 KB)
- .wrangler/ (708 KB)

### Large Files Analysis
| File | Size | Type | Action |
|------|------|------|--------|
| PowerShell MSI | 104.14 MB | Installer | REMOVE |
| quantum-audit.json | 9.15 MB | Report | REMOVE/R2 |
| main-*.js.map | 1.20 MB | Source map | REMOVE |
| package-lock.json | 931 KB | Lock file | KEEP |

---

## Dependency Analysis

### Runtime Dependencies (package.json)
```json
{
  "@cloudflare/ai": "^1.2.2",       // Cloudflare AI
  "@hono/zod-validator": "^0.2.2",  // Validation
  "hono": "^4.6.2",                  // Web framework
  "stripe": "^16.12.0",              // Payments
  "plaid": "^38.1.0",                // Banking
  "zod": "^3.23.8"                   // Schema validation
}
```

### Dev Dependencies (Notable)
- @cloudflare/workers-types
- wrangler (^4.39.0)
- vitest (testing)
- typescript
- esbuild (bundling)

---

## Database Structure

### D1 Databases
1. **coreflow360-agents** - Main application DB
   - Migrations: database/migrations/
   - Schemas: src/modules/finance/schema.sql

2. **mustbeviral-db** - Analytics DB

### Tables (from schema files)
- Users, Organizations, Roles
- Workflows, Tasks
- Payments, Invoices
- Agent configurations

---

## Security & Compliance

### Security Features
- JWT authentication (src/modules/auth/)
- ABAC authorization (src/modules/abac/)
- Rate limiting (Durable Objects)
- Input validation (Zod)
- Security middleware stack

### Secrets (via wrangler secret)
- AUTH_SECRET, JWT_SECRET
- STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET
- OPENAI_API_KEY, ANTHROPIC_API_KEY
- Various other API keys

---

## Optimization Opportunities

### Immediate Wins (119.5 MB reduction)
1. Remove PowerShell installer (104 MB)
2. Remove .venv directory (10.5 MB)
3. Remove large audit JSONs (9.1 MB)
4. Clean build artifacts (3.3 MB)
5. Remove redundant backups (1.8 MB)

### Future Optimizations
1. Move large reports to R2 storage
2. Implement Git LFS for remaining binaries
3. Automate cleanup in CI/CD
4. Add pre-commit size checks

---

## Risk Assessment

### Safe to Remove (No Risk)
- Binary installers (.msi)
- Python virtual environment
- Build outputs (dist/)
- Coverage reports
- Cache directories
- Temp files and logs

### Keep (Critical)
- All src/ TypeScript code
- wrangler.toml configurations
- Package files
- Database migrations
- GitHub workflows
- Documentation

---

## Validation Checklist

Before cleanup:
- [x] Cloudflare entry points identified
- [x] Dependencies mapped
- [x] Build chain verified
- [x] Database bindings confirmed
- [x] CI/CD workflows reviewed
- [x] No critical files in removal list

After cleanup (Phase 2):
- [ ] TypeScript compiles (`npm run type-check`)
- [ ] Tests pass (`npm run test`)
- [ ] Cloudflare deploys (`wrangler deploy --dry-run`)
- [ ] Frontend builds (`npm run build`)
- [ ] No broken imports