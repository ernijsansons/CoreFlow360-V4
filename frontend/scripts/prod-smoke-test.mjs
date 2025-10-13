#!/usr/bin/env node

/**
 * Automated production smoke test runner for CoreFlow360 V4
 * Executes the 25-step manual checklist against the live deployed site
 * and emits a Markdown summary to stdout.
 */

import { chromium, devices } from 'playwright'
import process from 'node:process'

const BASE_URL = 'https://main.coreflow360-frontend.pages.dev'
const CREDENTIALS = {
  email: 'founder@coreflow360.com',
  password: process.env.TEST_PASSWORD || '', // Set TEST_PASSWORD environment variable
}

const MUST_PASS = new Set([
  1, // Console errors
  14, // Logout
  16, // Login with valid credentials
  2, // Dashboard metrics
  3, // Charts render
  9, // Session persists
  17, // Protected routes
])

const HIGH_PRIORITY = new Set([4, 5, 18, 19, 20, 21])
const NICE_TO_HAVE = new Set([22, 23, 13, 11, 12])

const results = []

function recordResult(id, name, status, details = '', extras = {}) {
  results.push({
    id,
    name,
    status,
    details,
    ...extras,
  })
}

async function createSession(browser, options = {}) {
  const context =
    options.device && devices[options.device]
      ? await browser.newContext(devices[options.device])
      : await browser.newContext({
          viewport: options.viewport ?? { width: 1440, height: 900 },
          userAgent: options.userAgent,
        })

  const page = await context.newPage()
  const consoleErrors = []
  const pageErrors = []
  const networkEvents = []

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text())
    }
  })

  page.on('pageerror', (error) => {
    pageErrors.push(error.message)
  })

  page.on('response', async (response) => {
    const timing = response.request().timing()
    networkEvents.push({
      url: response.url(),
      status: response.status(),
      ok: response.ok(),
      timing,
    })
  })

  return { context, page, consoleErrors, pageErrors, networkEvents }
}

async function login(page, consoleErrors) {
  await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' })
  await page.waitForSelector('input[name="email"]', { timeout: 5000 })

  await page.fill('input[name="email"]', CREDENTIALS.email)
  await page.fill('input[name="password"]', CREDENTIALS.password)

  const beforeErrors = consoleErrors.length
  await page.click('button:has-text("Sign In Securely")', { timeout: 3000 })

  try {
    await page.waitForURL('**/dashboard*', { timeout: 10000 })
  } catch {
    // ignore – stay on page to capture failure state
  }

  await page.waitForTimeout(1500)

  return {
    redirectOk: page.url().includes('/dashboard'),
    newConsoleErrors: consoleErrors.length - beforeErrors,
  }
}

async function runPhase1to3(browser) {
  const session = await createSession(browser)
  const { page, consoleErrors, pageErrors } = session

  try {
    const loginResult = await login(page, consoleErrors)
    if (!loginResult.redirectOk) {
      const baseFailNote = `Unable to reach dashboard (current URL: ${page.url()})`
      recordResult(
        1,
        'Console Errors Check',
        'FAIL',
        `${baseFailNote}; console errors: ${consoleErrors.join(' | ') || 'none'}`
      )
      const followUp = [
        [2, 'Dashboard Display'],
        [3, 'Charts Rendering'],
        [4, 'Sidebar Navigation'],
        [5, 'Time Range Selector'],
        [6, 'Export Button'],
        [7, 'Refresh Button'],
        [8, 'Tabs Navigation'],
        [9, 'Session Persistence'],
        [10, 'User Menu'],
        [11, 'Command Palette'],
        [12, 'Notifications Dropdown'],
        [13, 'Theme Toggle'],
      ]
      for (const [id, name] of followUp) {
        recordResult(id, name, 'FAIL', baseFailNote)
      }
      return
    }

    await page.waitForSelector('text=Dashboard Overview', { timeout: 5000 })

    // Test 1: Console errors
    const react130 = consoleErrors.find((line) => line.includes('React Error #130'))
    const status1 =
      consoleErrors.length === 0 && pageErrors.length === 0
        ? 'PASS'
        : 'FAIL'
    recordResult(
      1,
      'Console Errors Check',
      status1,
      status1 === 'PASS'
        ? 'No console/page errors detected'
        : `Errors: ${[...consoleErrors, ...pageErrors].join(' | ')}`,
      { consoleErrors: [...consoleErrors], pageErrors: [...pageErrors], react130: !!react130 }
    )

    // Test 2: Dashboard metrics
    const metrics = ['Total Users', 'Total Revenue', 'Churn Rate', 'Active Projects']
    let metricsMissing = []
    for (const metric of metrics) {
      const visible = await page.getByText(metric, { exact: true }).isVisible().catch(() => false)
      if (!visible) metricsMissing.push(metric)
    }
    recordResult(
      2,
      'Dashboard Display',
      metricsMissing.length === 0 ? 'PASS' : 'FAIL',
      metricsMissing.length === 0
        ? 'All KPI cards visible'
        : `Missing metrics: ${metricsMissing.join(', ')}`
    )

    // Test 3: Charts Rendering
    const placeholderCount = await page.locator('text=Chart.js integration pending').count()
    recordResult(
      3,
      'Charts Rendering',
      placeholderCount === 0 ? 'PASS' : 'FAIL',
      placeholderCount === 0
        ? 'Revenue and User Growth charts rendered'
        : 'Charts still show placeholder copy ("Chart.js integration pending")'
    )

    // Test 4: Sidebar navigation
    const dashboardLink = page.getByRole('link', { name: 'Dashboard' })
    const crmMenu = page.locator('button[aria-label="CRM menu"]')
    const financeMenu = page.locator('button[aria-label="Finance menu"]')
    let sidebarIssues = []
    await dashboardLink.click({ timeout: 3000 }).catch(() => sidebarIssues.push('Dashboard link'))
    await crmMenu.click({ timeout: 3000 }).catch(() => sidebarIssues.push('CRM toggle'))
    const crmExpanded = await crmMenu.getAttribute('aria-expanded')
    if (crmExpanded !== 'true') sidebarIssues.push('CRM submenu')
    await financeMenu.click({ timeout: 3000 }).catch(() => sidebarIssues.push('Finance toggle'))
    const financeExpanded = await financeMenu.getAttribute('aria-expanded')
    if (financeExpanded !== 'true') sidebarIssues.push('Finance submenu')
    recordResult(
      4,
      'Sidebar Navigation',
      sidebarIssues.length === 0 ? 'PASS' : 'FAIL',
      sidebarIssues.length === 0 ? 'Sidebar links expanded correctly' : sidebarIssues.join(', ')
    )

    // Test 5: Time Range Selector
    const timeSelector = page.locator('button[role="combobox"]').first()
    await timeSelector.click({ timeout: 3000 })
    await page.getByRole('option', { name: 'Last 30 days' }).click({ timeout: 3000 })
    const triggerText = await timeSelector.innerText()
    recordResult(
      5,
      'Time Range Selector',
      triggerText.includes('Last 30 days') ? 'PASS' : 'FAIL',
      triggerText.trim()
    )

    // Test 6: Export Button
    const exportButton = page.getByRole('button', { name: /Export/ })
    const exportErrorBaseline = consoleErrors.length
    await exportButton.click({ timeout: 3000 }).catch(() => {})
    await page.waitForTimeout(500)
    recordResult(
      6,
      'Export Button',
      consoleErrors.length === exportErrorBaseline ? 'WARN' : 'FAIL',
      consoleErrors.length === exportErrorBaseline
        ? 'Button clickable but no visible action (expected placeholder)'
        : 'Console errors after clicking export'
    )

    // Test 7: Refresh Button
    const refreshButton = page.locator('button:has(svg[data-lucide="refresh-cw"])').first()
    await refreshButton.click({ timeout: 3000 }).catch(() => {})
    await page.waitForTimeout(500)
    const spinning = await refreshButton
      .locator('svg[data-lucide="refresh-cw"]')
      .evaluate((el) => el.classList.contains('animate-spin'))
      .catch(() => false)
    await page.waitForTimeout(2000)
    const spinCleared = await refreshButton
      .locator('svg[data-lucide="refresh-cw"]')
      .evaluate((el) => !el.classList.contains('animate-spin'))
      .catch(() => false)
    recordResult(
      7,
      'Refresh Button',
      spinning && spinCleared ? 'PASS' : 'FAIL',
      spinning && spinCleared ? 'Spinner animates and stops' : 'No spinner animation detected'
    )

    // Test 8: Tabs Navigation
    const tabs = ['Analytics', 'Reports', 'Overview']
    let tabIssues = []
    for (const tab of tabs) {
      const trigger = page.getByRole('tab', { name: tab })
      await trigger.click({ timeout: 3000 }).catch(() => tabIssues.push(`${tab} (click failed)`))
      await page.waitForTimeout(400)
      const active = await trigger.getAttribute('data-state')
      if (active !== 'active') tabIssues.push(`${tab} (not active)`)
    }
    recordResult(
      8,
      'Tabs Navigation',
      tabIssues.length === 0 ? 'PASS' : 'FAIL',
      tabIssues.length === 0 ? 'Overview/Analytics/Reports switch correctly' : tabIssues.join(', ')
    )

    // Test 9: Session Persistence
    await page.reload({ waitUntil: 'networkidle', timeout: 10000 })
    const stayedLoggedIn =
      page.url().includes('/dashboard') &&
      (await page.getByText('Dashboard Overview').isVisible().catch(() => false))
    recordResult(
      9,
      'Session Persistence',
      stayedLoggedIn ? 'PASS' : 'FAIL',
      stayedLoggedIn ? 'Still authenticated after reload' : 'Redirected away from dashboard'
    )

    // Test 10: User Menu
    const userMenu = page.getByRole('button', { name: /User menu for/i })
    await userMenu.click({ timeout: 3000 }).catch(() => {})
    const menuVisible = await page
      .locator('[role="menu"] >> text=Log out')
      .isVisible()
      .catch(() => false)
    recordResult(
      10,
      'User Menu',
      menuVisible ? 'PASS' : 'FAIL',
      menuVisible ? 'Dropdown opened' : 'Could not open user dropdown'
    )
    await page.keyboard.press('Escape').catch(() => {})

    // Test 11: Command Palette
    await page.keyboard.press('Control+K')
    await page.waitForTimeout(300)
    const paletteVisible = await page
      .locator('[role="dialog"][aria-label="Command Palette"]')
      .isVisible()
      .catch(() => false)
    await page.keyboard.press('Escape').catch(() => {})
    recordResult(
      11,
      'Command Palette',
      paletteVisible ? 'PASS' : 'FAIL',
      paletteVisible ? 'Opened via Ctrl+K' : 'Dialog did not open'
    )

    // Test 12: Notifications
    const notificationsButton = page.locator('button:has(svg[data-lucide="bell"])')
    await notificationsButton.click({ timeout: 3000 }).catch(() => {})
    const notificationsOpen = await page
      .locator('text=Notifications')
      .first()
      .isVisible()
      .catch(() => false)
    recordResult(
      12,
      'Notifications Dropdown',
      notificationsOpen ? 'PASS' : 'FAIL',
      notificationsOpen ? 'Dropdown visible' : 'No notification dropdown'
    )
    await page.keyboard.press('Escape').catch(() => {})

    // Test 13: Theme Toggle
    const themeToggle = page.getByRole('button', { name: 'Toggle theme' })
    await themeToggle.click({ timeout: 3000 }).catch(() => {})
    const themeMenuVisible = await page
      .locator('text=Light')
      .first()
      .isVisible()
      .catch(() => false)
    recordResult(
      13,
      'Theme Toggle',
      themeMenuVisible ? 'PASS' : 'FAIL',
      themeMenuVisible ? 'Theme options shown' : 'Theme menu missing'
    )
    await page.keyboard.press('Escape').catch(() => {})
  } catch (error) {
    console.error('Phase 1-3 failure:', error)
    throw error
  } finally {
    await session.context.close()
  }
}

async function runPhase4(browser) {
  const session = await createSession(browser)
  const { page, consoleErrors } = session

  try {
    // Login first to reach dashboard
    const loginResult = await login(page, consoleErrors)
    if (!loginResult.redirectOk) {
      const failNote = `Unable to login (current URL: ${page.url()})`
      recordResult(14, 'Logout Flow', 'FAIL', failNote)
      recordResult(15, 'Login Validation', 'FAIL', failNote)
      recordResult(16, 'Login with Valid Credentials', 'FAIL', failNote)
      recordResult(17, 'Protected Routes', 'FAIL', failNote)
      return
    }

    // Test 14: Logout
    await page.getByRole('button', { name: /User menu for/i }).click({ timeout: 3000 })
    await Promise.all([
      page.waitForURL('**/login', { timeout: 8000 }),
      page.locator('text=Log out').click({ timeout: 3000 }),
    ])
    const loggedOut = page.url().includes('/login')
    recordResult(
      14,
      'Logout Flow',
      loggedOut ? 'PASS' : 'FAIL',
      loggedOut ? 'Redirected to /login' : `Current URL: ${page.url()}`
    )

    // Test 15: Login Form Validation
    await page.waitForSelector('button:has-text("Sign In Securely")', { timeout: 5000 })
    await page.click('button:has-text("Sign In Securely")', { timeout: 3000 }).catch(() => {})
    await page.waitForTimeout(300)
    const emailError = await page.locator('text=Invalid email address').first().isVisible().catch(() => false)
    const passwordError = await page
      .locator('text=Password must be at least 8 characters')
      .first()
      .isVisible()
      .catch(() => false)
    recordResult(
      15,
      'Login Validation',
      emailError && passwordError ? 'PASS' : 'FAIL',
      `Email error: ${emailError}, Password error: ${passwordError}`
    )

    // Test 16: Login with Valid Credentials
    await page.fill('input[name="email"]', CREDENTIALS.email)
    await page.fill('input[name="password"]', CREDENTIALS.password)
    await Promise.all([
      page.waitForURL('**/dashboard*', { timeout: 10000 }),
      page.click('button:has-text("Sign In Securely")'),
    ])
    const react130 = consoleErrors.find((line) => line.includes('React Error #130'))
    recordResult(
      16,
      'Login with Valid Credentials',
      page.url().includes('/dashboard') && !react130 ? 'PASS' : 'FAIL',
      react130 ? 'React Error #130 encountered' : `URL after login: ${page.url()}`
    )

    // Test 17: Protected Routes
    await page.context().clearCookies()
    await page.evaluate(() => {
      localStorage.clear()
      sessionStorage.clear()
    })
    await page.goto(`${BASE_URL}/logout`, { waitUntil: 'domcontentloaded' }).catch(() => {})
    await page.goto(`${BASE_URL}/dashboard`, { waitUntil: 'networkidle' })
    const redirectedToLogin = page.url().includes('/login')
    await page.waitForSelector('input[name="email"]', { timeout: 5000 }).catch(() => {})
    await page.fill('input[name="email"]', CREDENTIALS.email)
    await page.fill('input[name="password"]', CREDENTIALS.password)
    await Promise.all([
      page.waitForURL('**/dashboard*', { timeout: 10000 }),
      page.click('button:has-text("Sign In Securely")'),
    ])
    const returnedToDashboard = page.url().includes('/dashboard')
    recordResult(
      17,
      'Protected Routes',
      redirectedToLogin && returnedToDashboard ? 'PASS' : 'FAIL',
      `Redirected while logged out: ${redirectedToLogin}, Restored after login: ${returnedToDashboard}`
    )
  } catch (error) {
    console.error('Phase 4 failure:', error)
    throw error
  } finally {
    await session.context.close()
  }
}

async function runPhase5(browser) {
  const session = await createSession(browser)
  const { page } = session

  try {
    // Ensure logged out
    await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' })

    // Test 18: Registration Link
    await page.locator('a[href="/register"], a[href="/auth/register"]').first().click({ timeout: 3000 })
    const onRegister = page.url().includes('/register') || page.url().includes('/auth/register')
    recordResult(
      18,
      'Registration Link',
      onRegister ? 'PASS' : 'FAIL',
      `URL: ${page.url()}`
    )

    // Test 19: Registration Form
    const emailField = page.locator('input[name="email"]')
    const hasForm = (await emailField.count()) > 0

    if (!hasForm) {
      recordResult(
        19,
        'Registration Form Validation',
        'FAIL',
        'Registration form fields not rendered at /register'
      )
    } else {
      await page.waitForSelector('button:has-text("Create account")', { timeout: 5000 }).catch(() => {})
      await page.click('button:has-text("Create account")', { timeout: 3000 }).catch(() => {})
      await page.waitForTimeout(300)
      const validationVisible = await page.locator('[role="alert"]').first().isVisible().catch(() => false)

      const testEmail = `automated+${Date.now()}@example.com`
      await page.fill('input[name="email"]', 'test')
      await page.fill('input[name="password"]', 'weak')
      await page.click('button:has-text("Create account")', { timeout: 3000 }).catch(() => {})
      const invalidEmail = await page.locator('text=Invalid email').first().isVisible().catch(() => false)

      await page.fill('input[name="firstName"]', 'Automation')
      await page.fill('input[name="lastName"]', 'Tester')
      await page.fill('input[name="company"]', 'QA Sandbox LLC')
      await page.fill('input[name="email"]', testEmail)
      await page.fill('input[name="password"]', 'StrongPass123!')
      await page.fill('input[name="confirmPassword"]', 'StrongPass123!')
      await page.check('input[name="agreeToTerms"]', { timeout: 3000 }).catch(() => {})
      recordResult(
        19,
        'Registration Form Validation',
        validationVisible && invalidEmail ? 'PASS' : 'WARN',
        `Initial validation shown: ${validationVisible}, Invalid email caught: ${invalidEmail}`
      )
    }

    // Test 20: Public Pages
    await page.goto(`${BASE_URL}/terms`, { waitUntil: 'networkidle' })
    const termsLoaded = await page.locator('text=Terms of Service').first().isVisible().catch(() => false)
    await page.goto(`${BASE_URL}/privacy`, { waitUntil: 'networkidle' })
    const privacyLoaded = await page.locator('text=Privacy Policy').first().isVisible().catch(() => false)
    recordResult(
      20,
      'Public Pages',
      termsLoaded && privacyLoaded ? 'PASS' : 'FAIL',
      `Terms: ${termsLoaded}, Privacy: ${privacyLoaded}`
    )

    // Test 21: 404 Handling
    await page.goto(`${BASE_URL}/nonexistentpage`, { waitUntil: 'networkidle' })
    const notFoundText = await page.locator('text=/Page not found/i').first().isVisible().catch(() => false)
    recordResult(
      21,
      '404 Handling',
      notFoundText ? 'PASS' : 'FAIL',
      notFoundText ? 'Custom 404 visible' : 'Fallback missing'
    )
  } catch (error) {
    console.error('Phase 5 failure:', error)
    throw error
  } finally {
    await session.context.close()
  }
}

async function runPhase6(browser) {
  // Mobile
  const mobileSession = await createSession(browser, { device: 'iPhone 12 Pro' })
  try {
    const { page } = mobileSession
    const mobileLogin = await login(page, mobileSession.consoleErrors)
    if (!mobileLogin.redirectOk) {
      recordResult(22, 'Mobile View', 'FAIL', `Unable to login on mobile context (URL: ${page.url()})`)
    } else {
      const sidebarCollapsed = await page.locator('button[aria-label="Toggle sidebar menu"]').isVisible().catch(() => false)
      recordResult(
        22,
        'Mobile View',
        sidebarCollapsed ? 'PASS' : 'FAIL',
        sidebarCollapsed ? 'Hamburger menu visible on mobile' : 'Sidebar toggle missing on mobile'
      )
    }
  } finally {
    await mobileSession.context.close()
  }

  // Tablet
  const tabletSession = await createSession(browser, { device: 'iPad Air' })
  try {
    const { page } = tabletSession
    const tabletLogin = await login(page, tabletSession.consoleErrors)
    if (!tabletLogin.redirectOk) {
      recordResult(23, 'Tablet View', 'FAIL', `Unable to login on tablet context (URL: ${page.url()})`)
    } else {
      const layoutOk = await page.locator('text=Dashboard Overview').isVisible().catch(() => false)
      recordResult(
        23,
        'Tablet View',
        layoutOk ? 'PASS' : 'FAIL',
        layoutOk ? 'Dashboard content visible on tablet' : 'Layout issues detected'
      )
    }
  } finally {
    await tabletSession.context.close()
  }
}

async function runPhase7(browser) {
  const session = await createSession(browser)
  const { page, networkEvents } = session

  try {
    const loginResult = await login(page, session.consoleErrors)
    if (!loginResult.redirectOk) {
      const failNote = `Unable to login for network/performance tests (URL: ${page.url()})`
      recordResult(24, 'Network Requests', 'FAIL', failNote)
      recordResult(25, 'Page Load Speed', 'FAIL', failNote)
      return
    }

    // Test 24: Network Requests
    const apiRequests = networkEvents.filter((evt) =>
      evt.url.includes('coreflow360-v4-prod.ernijs-ansons.workers.dev')
    )
    const failedRequests = apiRequests.filter((evt) => !evt.ok)
    recordResult(
      24,
      'Network Requests',
      apiRequests.length > 0 && failedRequests.length === 0 ? 'PASS' : 'FAIL',
      `API calls: ${apiRequests.length}, Failures: ${failedRequests.length}`
    )

    // Test 25: Page Load Speed
    await page.context().clearCookies()
    await page.goto(BASE_URL, { waitUntil: 'load' })
    const loadDuration = await page
      .evaluate(() => performance.getEntriesByType('navigation')[0]?.duration ?? 0)
      .catch(() => 0)
    recordResult(
      25,
      'Page Load Speed',
      loadDuration && loadDuration < 3000 ? 'PASS' : 'WARN',
      `Load duration: ${Math.round(loadDuration)} ms`
    )
  } catch (error) {
    console.error('Phase 7 failure:', error)
    throw error
  } finally {
    await session.context.close()
  }
}

function summarize() {
  const counts = results.reduce(
    (acc, item) => {
      acc[item.status] = (acc[item.status] ?? 0) + 1
      return acc
    },
    {}
  )

  const mustPassFailures = results.filter(
    (item) => MUST_PASS.has(item.id) && item.status !== 'PASS'
  )
  const highPriorityFailures = results.filter(
    (item) => HIGH_PRIORITY.has(item.id) && item.status !== 'PASS'
  )

  console.log('## CoreFlow360 V4 – Production Smoke Test Results')
  console.log(`Date: ${new Date().toISOString()}`)
  console.log('')
  console.log(`Total Tests: ${results.length}`)
  console.log(
    `Pass: ${counts.PASS ?? 0} | Warn: ${counts.WARN ?? 0} | Fail: ${counts.FAIL ?? 0} | Skip: ${counts.SKIP ?? 0}`
  )
  console.log('')

  if (mustPassFailures.length > 0) {
    console.log('### 🚨 Must-Pass Failures')
    for (const item of mustPassFailures) {
      console.log(`- Test ${item.id} – ${item.name}: ${item.status} (${item.details})`)
    }
    console.log('')
  }

  if (highPriorityFailures.length > 0) {
    console.log('### ⚠️ High Priority Issues')
    for (const item of highPriorityFailures) {
      console.log(`- Test ${item.id} – ${item.name}: ${item.status} (${item.details})`)
    }
    console.log('')
  }

  console.log('### Detailed Results')
  for (const item of results.sort((a, b) => a.id - b.id)) {
    console.log(`- Test ${item.id}: ${item.name} — ${item.status}${item.details ? ` (${item.details})` : ''}`)
  }
}

async function main() {
  const browser = await chromium.launch({ headless: true })

  try {
    await runPhase1to3(browser)
    await runPhase4(browser)
    await runPhase5(browser)
    await runPhase6(browser)
    await runPhase7(browser)
  } catch (error) {
    console.error('Smoke test aborted:', error)
  } finally {
    await browser.close()
  }

  summarize()
}

await main()
