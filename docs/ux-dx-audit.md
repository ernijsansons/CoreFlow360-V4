# CoreFlow360 V4 – UX & DX Audit

## Top Findings
- Primary “Start Free Trial” CTA is a dead button with no navigation or event tracking, so first-time users cannot reach onboarding without manually finding `/auth/register` (`frontend/src/components/marketing/HeroSection.tsx:47`).
- Header CTAs link to `/register`, but the router only exposes `/auth/register`, generating 404s on both desktop and mobile menus (`frontend/src/components/marketing/MarketingHeader.tsx:42`, `frontend/src/routes/auth/register.tsx:19`).
- The app shells twice before rendering content: `main.tsx` blocks with alerts and `App.tsx` lazy-loads the router after mount, delaying LCP and increasing perceived instability (`frontend/src/main.tsx:16`, `frontend/src/App.tsx:52`).
- No skip-to-content landmark, inconsistent landmark usage, and missing `aria-expanded` on the mobile menu hinder keyboard navigation (`frontend/src/components/marketing/MarketingLayout.tsx:15`, `frontend/src/components/marketing/MarketingHeader.tsx:60`).
- Production messaging leans on inflated metrics with no proof (e.g., `StatsBanner` claims “$2.8B revenue managed”), eroding trust and distracting from real product value (`frontend/src/routes/landing.tsx:14`).

## Sitemap & Key Journeys
| Flow | Entry Route(s) | Notes |
| --- | --- | --- |
| Marketing discovery | `/landing`, `/pricing`, `/about`, `/contact`, `/help`, `/ai-monitoring`, `/support` (`frontend/src/routes/*.tsx`) | Large sitemap but fragmented; core value prop buried under “AI-first” jargon. |
| Signup & onboarding | `/auth/register`, `/auth/verify-email`, `/login` (`frontend/src/routes/auth/*.tsx`) | Register form validates well but CTA is unreachable from marketing unless user edits URL. |
| Authenticated workspace | `/dashboard/*`, `/crm/*`, `/finance/*`, `/settings/*`, `/admin/*` (`frontend/src/routes/{dashboard,crm,finance,settings,admin}`) | Majority of routes depend on mocked data (`frontend/src/routes/dashboard/stats.tsx` etc.); orientation relies on sidebar. |
| Support & collaboration | `/chat/*`, `/reports/*`, `/system/*` | Dense feature list with little guidance; Onboarding tour component exists but only renders after auth (`frontend/src/components/onboarding/OnboardingTour.tsx:18`). |

First render always redirects `/` → `/landing` when unauthenticated (`frontend/src/routes/index.tsx:4`), so the first 10 seconds must resolve the “what is this?” question.

## First 10 Seconds Assessment
- Hero headline “Run Multiple Businesses on Autopilot” is clear, but CTA buttons lack navigation and analytics hooks (`frontend/src/components/marketing/HeroSection.tsx:47`).
- “AI-First Platform for Serial Entrepreneurs” badge adds jargon without proving value.
- Trust stats are static placeholders (`frontend/src/routes/landing.tsx:14`) and risk immediate credibility loss.
- Loading experience is rough: a blocking loading screen sits behind alerts, and hydration is delayed by lazy router import (`frontend/index.html:74`, `frontend/src/App.tsx:52`).
- Google Analytics uses `G-PLACEHOLDER`, so no real telemetry is captured (`frontend/index.html:10`).

**Recommendation:** Convert CTAs to `<Link asChild>` with event tracking, replace vanity stats with proof (logos, testimonials), and preload the router to avoid double loading.

## UX & Interaction Friction
- **Navigation parity:** Desktop header exposes `/marketing/pricing` while TanStack router only defines `/pricing`, producing a blank page (`frontend/src/components/marketing/MarketingHeader.tsx:32`, `frontend/src/routes/pricing.tsx:5`).
- **Mobile menu accessibility:** Toggle button lacks `aria-expanded` and `aria-controls`, hiding the expanded state from assistive tech (`frontend/src/components/marketing/MarketingHeader.tsx:60`).
- **State management:** Many high-value pages use static placeholders instead of loading/empty/error states (e.g., `/dashboard/stats` always renders fake “business-founder-001” data – `frontend/src/routes/dashboard/index.tsx:42`).
- **Copy clarity:** Complex modules (e.g., AI monitoring) drop users into dense tables with no quick primer or empty-state guidance (`frontend/src/routes/ai-monitoring.tsx:22`).
- **Entity switching:** `Header` renders account initials but profile actions are non-functional (`frontend/src/components/header.tsx:67`).

## Accessibility Audit
- No skip link before the header; keyboard users must tab through full navigation on every page (`frontend/src/components/marketing/MarketingLayout.tsx:15`).
- Mobile nav toggle lacks `aria-expanded` to expose open/closed state (`frontend/src/components/marketing/MarketingHeader.tsx:60`).
- Toast system and alert components mount outside landmarks, but `<main>` lacks unique IDs, making “skip to content” implementation harder (`frontend/src/components/marketing/MarketingLayout.tsx:14`).
- Hero CTA is a button with no `type="button"` nor actionable handler; screen readers announce it but activation does nothing (`frontend/src/components/marketing/HeroSection.tsx:47`).
- High-contrast mode is respected globally (`frontend/src/styles/globals.css:805`), but focus outlines rely on the custom `focus-ring` class—ensure every interactive component inherits it (audit added via axe script).

## Front-end Performance Risks
- Router is lazy-imported after mount, forcing an extra main-thread trip before content appears (LCP regression risk) (`frontend/src/App.tsx:52`).
- `main.tsx` performs DOM writes and blocking `alert` calls if React validation fails, which can halt rendering in production (`frontend/src/main.tsx:16`).
- TanStack route tree (`frontend/src/routeTree.gen.ts`, 53 KB) ships every route config up front even for anonymous visitors—consider code-splitting marketing vs. app shells.
- `_headers` forces `Cache-Control: public, max-age=0, must-revalidate` for HTML responses; pair with `stale-while-revalidate` to cut time-to-first-byte on repeat visits (`frontend/_headers:21`).
- Large amounts of console logging and emoji slow hydration in production due to `drop_console` running only at build time; ensure logging is stripped for Cloudflare builds.

## Copy & Micro-UX Observations
- Registration success screen references `watch('email')`, which is empty when the user aborts registration, yielding “undefined” in the message (`frontend/src/routes/auth/register.tsx:141`).
- Finance/CRM dashboards default to filler numbers with no tooltips describing source or update cadence (`frontend/src/routes/dashboard/index.tsx:83`).
- B2B language mixes “serial entrepreneurs” with “Fortune-50 grade” in README; unify messaging for target segment.
- Provide inline hints for advanced AI features (e.g., voice agent) and link to docs for context-sensitive help.

## Automation & DX Enhancements
- Added `scripts/audit/run-axe-audit.mjs` for Playwright + axe smoke checks and `scripts/audit/worker-latency.mjs` for Worker benchmarks. Exposed via `npm run audit:*` scripts.
- Recommend wiring `lhci autorun` (config in `scripts/audit/lighthouserc.json`) to CI for PR gating and nightly regressions.
- Document how to start both frontend and worker together; current `npm run dev:full` is undocumented and fails if Wrangler isn’t authenticated.

## Prioritized Backlog
**P0 – fix immediately**
- Wire hero CTA and header buttons to `/auth/register` with analytics events (`frontend/src/components/marketing/HeroSection.tsx:47`, `frontend/src/components/marketing/MarketingHeader.tsx:42`).
- Remove blocking alerts and eager DOM mutations from `main.tsx` / `index.html`, and preload the router bundle (`frontend/src/main.tsx:16`, `frontend/index.html:93`, `frontend/src/App.tsx:52`).
- Publish skip-to-content link and add `aria-expanded`/`aria-controls` for the mobile nav (`frontend/src/components/marketing/MarketingHeader.tsx:60`).

**P1 – medium priority**
- Introduce real loading/empty/error states for dashboard, CRM, and finance routes; replace hard-coded IDs (`frontend/src/routes/dashboard/index.tsx:28`, `frontend/src/routes/crm/leads.tsx:30`).
- Consolidate trust messaging with real proof (logos, testimonials) and replace placeholder stats (`frontend/src/routes/landing.tsx:14`).
- Add route-level meta titles/descriptions for SEO and analytics clarity (`frontend/src/routes/landing.tsx:7`, `frontend/src/routes/pricing.tsx:5`).
- Expand Playwright coverage to authenticated flows with MSW mocks and integrate axe-runner into CI.

**P2 – longer term**
- Split marketing bundle from app shell using TanStack route groups to reduce first-load JS (`frontend/src/routeTree.gen.ts`).
- Replace GA placeholder with privacy-compliant telemetry (e.g., Microsoft Clarity + web-vitals reporting) (`frontend/index.html:10`).
- Audit copy consistency (enterprise vs SMB) and create a voice/tone guide to streamline future updates (README.md:1).
