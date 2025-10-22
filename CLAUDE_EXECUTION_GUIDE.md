# CoreFlow360 Marketing Revamp Execution Guide (for Claude Code)

## Overview
This document defines the full end-to-end workflow Claude Code should execute to transform the CoreFlow360 marketing web experience into a Fortune-50 ready presentation site. Follow the phases strictly; confirm completion of each exit criterion before moving on.

---

## Phase 0: Project Spin-Up
1. Clone the latest coreflow360-frontend repository and install dependencies (pnpm install).
2. Create a dedicated branch marketing-refresh/<date> for this initiative.
3. Stand up collaboration artifacts:
   - Create /docs/marketing-refresh/ directory in repo for working notes.
   - Generate project-charter.md capturing objectives, KPIs, stakeholders, timelines.
   - Initialize /docs/marketing-refresh/status-log.md for daily progress snapshots.
4. Configure design collaboration hooks:
   - Ensure Figma project URL is documented in project-charter.md.
   - Create /docs/marketing-refresh/design-requests.md to track asset needs.
5. Validate tooling:
   - Run lint/test (pnpm lint, pnpm test --watch=false).
   - Capture initial Lighthouse scores for /landing, /pricing, /enterprise using pnpm lighthouse --url <route>; store reports in /docs/marketing-refresh/baseline-metrics/.

Exit Criteria: Repo branch ready, baseline metrics archived, charter + logs committed.

---

## Phase 1: Brand and Messaging Foundation
1. Produce /docs/marketing-refresh/positioning-brief.md summarizing target personas, pain points, CoreFlow360 differentiators, tone of voice.
2. Build /docs/marketing-refresh/visual-language.md with palette tokens, typography scale, motion principles (reference Figma components).
3. Draft testimonial and proof-point library in /docs/marketing-refresh/proof-library.csv.
4. Update 	ailwind.config.ts (or design token source) with new color tokens and typography variables defined in visual-language doc (no CSS refactors yet).
5. Commit and push branch for review.

Exit Criteria: Positioning brief, visual language, and tokens merged into branch; stakeholders sign off.

---

## Phase 2: Information Architecture and Content Strategy
1. Build /docs/marketing-refresh/sitemap-v2.md containing revised navigation, URL map, and audience mapping per page.
2. Create /docs/marketing-refresh/content-briefs/ directory with briefs for:
   - landing.md
   - pricing.md
   - nterprise.md
   - products.md
   - bout.md
   - contact.md
   - security.md
   - privacy.md
   - 	erms.md
3. Define SEO targets in /docs/marketing-refresh/seo-keywords.csv (keyword, intent, target page, notes).
4. Outline lead funnel instrumentation in /docs/marketing-refresh/analytics-plan.md (events, properties, GA4/Segment mapping).
5. Submit documentation PR for marketing approval before implementation.

Exit Criteria: Approved IA, content briefs, SEO and analytics plans.

---

## Phase 3: Experience & Visual Design Implementation
1. Translate approved Figma frames into reusable UI primitives under src/components/marketing/.
2. Build a dedicated layout shell src/layouts/MarketingLayout.tsx with mega-nav, footer, trust ribbon, CTA variants.
3. Implement component library:
   - HeroSection, StatsBanner, ProofCarousel, FeatureGrid, SecurityPanel, CTAForm, FAQAccordion, FooterLegal.
   - Ensure responsive breakpoints (320px, 768px, 1024px, 1440px) are pixel-aligned with Figma.
4. Wire design tokens into Tailwind/custom CSS (update src/styles/globals.css or equivalent).
5. Add Storybook stories (stories/marketing/*.stories.tsx) and run pnpm storybook locally to validate components.
6. Commit partial implementation for review.

Exit Criteria: Marketing component library parity with Figma, Storybook passes lint/test, responsive QA complete.

---

## Phase 4: Content Authoring & Page Assembly
1. Implement new routes under src/routes/marketing/:
   - /landing
   - /pricing
   - /enterprise
   - /products
   - /about
   - /contact
   - /security
   - /privacy
   - /terms
2. Populate pages with content derived from briefs; ensure value props, ROI metrics, enterprise assurances, and CTAs align with the positioning doc.
3. Integrate interactive modules:
   - ROI calculator (inputs, output summary, CTA).
   - Case study carousel (logos, metrics, quotes).
   - Compliance badge grid (SOC 2, GDPR, ISO text).
4. Replace mailto CTAs with lead capture form backed by marketing automation (mock service if backend unavailable).
5. Remove outdated/test routes from public build and adjust navigation.
6. Update sitemap and robots configuration for new IA.

Exit Criteria: All marketing pages production-ready with content, navigation updated, no placeholder text remains.

---

## Phase 5: Accessibility & Compliance Hardening
1. Run automated checks (pnpm axe, pnpm test:accessibility) across marketing routes.
2. Perform manual keyboard traversal; document findings in /docs/marketing-refresh/accessibility-report.md and fix issues.
3. Audit color contrast; adjust tokens or component styles to satisfy WCAG 2.2 AA.
4. Add semantic landmarks (<header>, <nav>, <main>, <footer>), ARIA labels, and skip-link support.
5. Draft security-and-compliance.md summarizing data protections, reviewed by legal.

Exit Criteria: Accessibility report records zero blocking issues, compliance messaging approved.

---

## Phase 6: Performance, Analytics, and QA
1. Introduce marketing bundle code-splitting (lazy load app shell) and confirm using build analyzer (pnpm analyze).
2. Configure GA4/Segment IDs, consent banner, and event instrumentation defined in analytics plan.
3. Run Lighthouse CI (pnpm lighthouse --collect --upload) to verify >=95 scores (Performance, Accessibility, Best Practices, SEO) for each marketing route.
4. Execute end-to-end tests (pnpm cypress run --spec "marketing/**").
5. Update /docs/marketing-refresh/status-log.md with metric deltas and attach final reports.

Exit Criteria: Performance targets met, analytics verified, QA suite green.

---

## Phase 7: Launch & Post-Launch
1. Prepare release notes in /docs/marketing-refresh/release-plan.md (timeline, owners, rollback steps).
2. Merge branch via approved PR; tag release marketing-refresh-v1.
3. Deploy to staging and run smoke tests; once approved, promote to production.
4. Monitor analytics dashboards for 72 hours; log anomalies in status log and create follow-up tickets for iterative CRO tests.
5. Archive documentation to /docs/marketing-refresh/archive/ and close project with retro notes (etro.md).

Exit Criteria: Production deploy verified, monitoring clean, retro captured.

---

## Governance Notes
- Commit frequently with conventional messages (eat(marketing): ...).
- Require design + marketing stakeholder review on every PR touching UI copy or visuals.
- Maintain alignment with program charter KPIs at weekly checkpoints; update status log even on no-change days.
- Keep all assets ASCII-compatible; store large binaries in design tooling, not repo.

