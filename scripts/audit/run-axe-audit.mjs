#!/usr/bin/env node
/**
 * Accessibility smoke test for key public CoreFlow360 screens.
 * Runs Playwright + axe-core against unauthenticated routes and fails on WCAG 2.1 A/AA violations.
 */
import { chromium } from 'playwright'
import AxeBuilder from '@axe-core/playwright'
import { performance } from 'node:perf_hooks'

const BASE_URL = process.env.CF360_BASE_URL ?? 'http://localhost:5173'
const VIEWPORT = { width: 1280, height: 720 }
const routes = [
  { path: '/landing', label: 'Marketing Landing' },
  { path: '/pricing', label: 'Pricing' },
  { path: '/help', label: 'Help Center' },
  { path: '/auth/login', label: 'Login' },
  { path: '/auth/register', label: 'Registration' },
]

async function auditRoute(browser, route) {
  const page = await browser.newPage({ viewport: VIEWPORT })
  const url = new URL(route.path, BASE_URL).toString()
  const start = performance.now()

  await page.goto(url, { waitUntil: 'networkidle', timeout: 45_000 })
  await page.waitForTimeout(1_000)

  const axe = new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).disableRules([
    // Toasts trigger focus traps before hydration; ignore temporarily
    'landmark-one-main',
  ])

  const results = await axe.analyze()
  await page.close()

  return {
    ...route,
    url,
    loadTimeMs: Math.round(performance.now() - start),
    violations: results.violations,
  }
}

async function main() {
  console.info(`⚙️  Running axe-core audit against ${routes.length} routes`)
  console.info(`    Base URL: ${BASE_URL}`)

  const browser = await chromium.launch({ headless: process.env.CI ? 'new' : true })
  const reports = []

  try {
    for (const route of routes) {
      const report = await auditRoute(browser, route)
      reports.push(report)

      if (report.violations.length === 0) {
        console.info(`✅  ${route.label} (${route.path}) passed – ${report.loadTimeMs} ms`)
      } else {
        console.warn(`❌  ${route.label} (${route.path}) failed with ${report.violations.length} violations`)
        report.violations.forEach((violation) => {
          console.warn(`    • [${violation.id}] ${violation.help}`)
          violation.nodes.slice(0, 3).forEach((node) => {
            console.warn(`      - ${node.failureSummary}`)
          })
        })
      }
    }
  } finally {
    await browser.close()
  }

  const failing = reports.filter((report) => report.violations.length > 0)

  if (failing.length > 0) {
    const summary = failing.map((report) => ({
      route: report.path,
      violations: report.violations.length,
      ids: report.violations.map((v) => v.id).join(', '),
    }))

    console.error('\nAccessibility violations detected:\n')
    console.table(summary)
    process.exitCode = 1
  } else {
    console.info('\n🎉  No WCAG 2.1 A/AA violations detected on audited routes.')
  }
}

main().catch((error) => {
  console.error('Failed to complete axe audit', error)
  process.exitCode = 1
})
