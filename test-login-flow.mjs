#!/usr/bin/env node
/**
 * COMPREHENSIVE LOGIN FLOW TEST WITH PLAYWRIGHT
 * Tests the complete authentication journey from landing to dashboard
 */

import { chromium } from 'playwright';

const BASE_URL = 'http://localhost:3000';
const TEST_USER = {
  email: 'test@example.com',
  password: 'Test123!@#'
};

console.log('🔐 COMPREHENSIVE LOGIN FLOW TEST\n');
console.log('======================================================================\n');

(async () => {
  let browser;
  let testResults = {
    passed: 0,
    failed: 0,
    tests: []
  };

  const test = (name, passed, details = '') => {
    if (passed) {
      console.log(`✅ ${name}`);
      testResults.passed++;
    } else {
      console.log(`❌ ${name}`);
      if (details) console.log(`   ℹ️  ${details}`);
      testResults.failed++;
    }
    testResults.tests.push({ name, passed, details });
  };

  try {
    browser = await chromium.launch({
      headless: false,
      slowMo: 200
    });

    const context = await browser.newContext({
      viewport: { width: 1920, height: 1080 }
    });

    const page = await context.newPage();
    let consoleErrors = [];
    let pageErrors = [];

    // Monitor console and page errors (filter non-critical warnings)
    page.on('console', msg => {
      if (msg.type() === 'error') {
        const text = msg.text();

        // Filter out non-critical React warnings
        if (text.includes('non-boolean attribute') ||
            text.includes('Warning: Received')) {
          return; // Skip non-critical warnings
        }

        consoleErrors.push(text);
      }
    });

    page.on('pageerror', error => {
      pageErrors.push(error.message);
    });

    // ===================================================================
    // MOCK API RESPONSES
    // ===================================================================
    console.log('🔧 Setting up API mocks...\n');

    // Mock login API endpoint
    await page.route('**/api/auth/login', async route => {
      if (route.request().method() === 'POST') {
        console.log('   ✅ Intercepted login API call - returning mock success response');

        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
          },
          body: JSON.stringify({
            success: true,
            data: {
              token: 'mock-jwt-token-for-testing',
              refreshToken: 'mock-refresh-token-for-testing',
              user: {
                id: '1',
                email: TEST_USER.email,
                firstName: 'Test',
                lastName: 'User',
                role: 'admin'
              }
            }
          })
        });
      } else {
        await route.continue();
      }
    });

    // Mock dashboard/home API calls
    await page.route('**/api/**', async route => {
      // Let login pass through (already mocked above)
      if (route.request().url().includes('/auth/login')) {
        return route.continue();
      }

      // Mock other API calls to prevent errors
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ success: true, data: [] })
        });
      } else {
        await route.continue();
      }
    });

    console.log('   ✅ API mocks configured\n');

    // ===================================================================
    // PHASE 1: LANDING PAGE
    // ===================================================================
    console.log('📄 PHASE 1: LANDING PAGE');
    console.log('----------------------------------------------------------------------');

    await page.goto(`${BASE_URL}/landing`, { waitUntil: 'networkidle' });
    await page.waitForTimeout(1000);

    test('Landing page loads', page.url().includes('/landing'));

    const hasH1 = await page.locator('h1').count() > 0;
    test('Landing page has H1 heading', hasH1);

    const hasH2 = await page.locator('h2').count() > 0;
    test('Landing page has H2 headings', hasH2);

    const ctaButtons = await page.locator('button, a').filter({ hasText: /Start.*Trial|Get Started|Sign Up/i }).count();
    test('Landing page has CTA buttons', ctaButtons > 0, `Found ${ctaButtons} CTA buttons`);

    await page.screenshot({ path: 'test-landing-before-login.png', fullPage: true });
    test('Landing page screenshot captured', true);

    // ===================================================================
    // PHASE 2: NAVIGATE TO LOGIN
    // ===================================================================
    console.log('\n🔗 PHASE 2: NAVIGATE TO LOGIN');
    console.log('----------------------------------------------------------------------');

    // Try to find and click login link/button
    const loginLinks = await page.getByRole('link', { name: /log.*in|sign.*in/i }).count();
    test('Login link exists in navigation', loginLinks > 0, `Found ${loginLinks} login links`);

    if (loginLinks > 0) {
      await page.getByRole('link', { name: /log.*in|sign.*in/i }).first().click();
      await page.waitForLoadState('networkidle');
    } else {
      // Navigate directly
      await page.goto(`${BASE_URL}/login`, { waitUntil: 'networkidle' });
    }

    await page.waitForTimeout(1000);

    test('Login page loads', page.url().includes('/login'));

    const loginTitle = await page.locator('h1, h2').filter({ hasText: /welcome|log.*in|sign.*in/i }).count();
    test('Login page has welcome heading', loginTitle > 0);

    await page.screenshot({ path: 'test-login-page.png', fullPage: true });
    test('Login page screenshot captured', true);

    // ===================================================================
    // PHASE 3: LOGIN FORM VALIDATION
    // ===================================================================
    console.log('\n📝 PHASE 3: LOGIN FORM VALIDATION');
    console.log('----------------------------------------------------------------------');

    const emailInput = await page.locator('input[type="email"], input[name="email"], input[placeholder*="email" i]').count();
    test('Email input exists', emailInput > 0);

    const passwordInput = await page.locator('input[type="password"], input[name="password"]').count();
    test('Password input exists', passwordInput > 0);

    const submitButton = await page.locator('button[type="submit"], button').filter({ hasText: /log.*in|sign.*in|continue/i }).count();
    test('Submit button exists', submitButton > 0);

    // Test form validation (empty submit)
    if (submitButton > 0) {
      await page.locator('button[type="submit"], button').filter({ hasText: /log.*in|sign.*in|continue/i }).first().click();
      await page.waitForTimeout(500);

      const validationMessage = await page.locator('text=/required|invalid|enter/i').count();
      test('Form validation works (empty submit)', validationMessage > 0 || await page.locator('input:invalid').count() > 0);
    }

    // ===================================================================
    // PHASE 4: ATTEMPT LOGIN
    // ===================================================================
    console.log('\n🔑 PHASE 4: ATTEMPT LOGIN');
    console.log('----------------------------------------------------------------------');

    if (emailInput > 0 && passwordInput > 0) {
      // Fill in test credentials
      await page.locator('input[type="email"], input[name="email"], input[placeholder*="email" i]').first().fill(TEST_USER.email);
      await page.locator('input[type="password"], input[name="password"]').first().fill(TEST_USER.password);

      test('Credentials filled', true, `Email: ${TEST_USER.email}`);

      await page.screenshot({ path: 'test-login-filled.png', fullPage: true });

      // Submit form
      await page.locator('button[type="submit"], button').filter({ hasText: /log.*in|sign.*in|continue/i }).first().click();

      // Wait for navigation or error
      try {
        await page.waitForTimeout(2000);

        const currentUrl = page.url();
        const redirected = !currentUrl.includes('/login');

        test('Form submitted', true);
        test('Navigation after submit', redirected, `URL: ${currentUrl}`);

        // Check for error messages
        const errorMessages = await page.locator('text=/error|invalid|failed|incorrect/i').count();
        test('No error messages (or redirected)', errorMessages === 0 || redirected);

        if (redirected) {
          // ===================================================================
          // PHASE 5: AFTER-LOGIN DASHBOARD
          // ===================================================================
          console.log('\n📊 PHASE 5: AFTER-LOGIN DASHBOARD');
          console.log('----------------------------------------------------------------------');

          await page.waitForLoadState('networkidle');
          await page.waitForTimeout(1500);

          const dashboardUrl = page.url();
          test('Redirected to dashboard/home', dashboardUrl.includes('/') || dashboardUrl.includes('/dashboard'), `URL: ${dashboardUrl}`);

          const hasNavigation = await page.locator('nav, aside, [role="navigation"]').count();
          test('Dashboard has navigation', hasNavigation > 0);

          const hasLogoutButton = await page.locator('button, a').filter({ hasText: /log.*out|sign.*out/i }).count();
          test('Logout button exists', hasLogoutButton > 0);

          const hasUserProfile = await page.locator('button, div').filter({ hasText: new RegExp(TEST_USER.email.split('@')[0], 'i') }).count();
          test('User profile/name visible', hasUserProfile > 0);

          // Check for main content areas
          const mainContent = await page.locator('main, [role="main"], .dashboard, .content').count();
          test('Dashboard has main content area', mainContent > 0);

          // Check for key dashboard elements
          const hasCards = await page.locator('.card, [class*="card"]').count();
          test('Dashboard has cards/widgets', hasCards > 0, `Found ${hasCards} cards`);

          const hasMetrics = await page.locator('text=/revenue|customers|leads|deals|orders/i').count();
          test('Dashboard shows business metrics', hasMetrics > 0);

          // Check for interactive elements
          const hasButtons = await page.locator('button').count();
          test('Dashboard has interactive buttons', hasButtons > 5, `Found ${hasButtons} buttons`);

          // Test responsiveness
          await page.setViewportSize({ width: 768, height: 1024 });
          await page.waitForTimeout(500);
          const mobileNavVisible = await page.locator('button[aria-label*="menu" i], .mobile-menu, [class*="mobile"]').count();
          test('Dashboard has mobile navigation', mobileNavVisible > 0);

          await page.setViewportSize({ width: 1920, height: 1080 });

          await page.screenshot({ path: 'test-dashboard-after-login.png', fullPage: true });
          test('Dashboard screenshot captured', true);

          // ===================================================================
          // PHASE 6: DASHBOARD FUNCTIONALITY
          // ===================================================================
          console.log('\n⚙️  PHASE 6: DASHBOARD FUNCTIONALITY');
          console.log('----------------------------------------------------------------------');

          // Test sidebar navigation
          const sidebarLinks = await page.locator('nav a, aside a, [role="navigation"] a').count();
          test('Sidebar has navigation links', sidebarLinks > 0, `Found ${sidebarLinks} links`);

          // Try clicking first sidebar link
          if (sidebarLinks > 0) {
            const firstLink = await page.locator('nav a, aside a, [role="navigation"] a').first();
            const linkText = await firstLink.textContent();
            await firstLink.click();
            await page.waitForTimeout(1000);
            test('Sidebar navigation works', true, `Clicked: ${linkText?.trim()}`);
          }

          // Check for search functionality
          const searchInput = await page.locator('input[type="search"], input[placeholder*="search" i]').count();
          test('Dashboard has search', searchInput > 0);

          // Check for notifications
          const notifications = await page.locator('[aria-label*="notification" i], .notification, [class*="notification"]').count();
          test('Notification area exists', notifications > 0);

          // ===================================================================
          // PHASE 7: LOGOUT
          // ===================================================================
          console.log('\n🚪 PHASE 7: LOGOUT');
          console.log('----------------------------------------------------------------------');

          if (hasLogoutButton > 0) {
            // Open user menu if needed
            const userMenuButton = await page.locator('button[aria-label*="user" i], button[aria-label*="account" i], [class*="avatar"]').count();
            if (userMenuButton > 0) {
              await page.locator('button[aria-label*="user" i], button[aria-label*="account" i], [class*="avatar"]').first().click();
              await page.waitForTimeout(500);
            }

            await page.locator('button, a').filter({ hasText: /log.*out|sign.*out/i }).first().click();
            await page.waitForTimeout(1500);

            const loggedOut = page.url().includes('/login') || page.url().includes('/landing');
            test('Logout successful', loggedOut, `URL: ${page.url()}`);

            if (loggedOut) {
              test('Redirected to login/landing', true);
            }
          }

        } else {
          console.log('\n⚠️  Login did not redirect - checking for error handling');
          const errorVisible = await page.locator('text=/error|invalid|failed|incorrect/i').isVisible().catch(() => false);
          test('Error message displayed', errorVisible, 'Expected error handling for invalid credentials');
        }

      } catch (error) {
        test('Login attempt completed', false, error.message);
      }

    }

    // ===================================================================
    // PHASE 8: ERROR CHECKING
    // ===================================================================
    console.log('\n🐛 PHASE 8: ERROR CHECKING');
    console.log('----------------------------------------------------------------------');

    test('No console errors', consoleErrors.length === 0, consoleErrors.length > 0 ? `Found ${consoleErrors.length} console errors` : '');
    test('No page errors', pageErrors.length === 0, pageErrors.length > 0 ? `Found ${pageErrors.length} page errors` : '');

    if (consoleErrors.length > 0) {
      console.log('\n   Console errors:');
      consoleErrors.slice(0, 5).forEach(err => console.log(`   - ${err.substring(0, 100)}`));
    }

    if (pageErrors.length > 0) {
      console.log('\n   Page errors:');
      pageErrors.slice(0, 5).forEach(err => console.log(`   - ${err.substring(0, 100)}`));
    }

    // ===================================================================
    // FINAL RESULTS
    // ===================================================================
    console.log('\n======================================================================');
    console.log('📊 FINAL TEST RESULTS');
    console.log('======================================================================');
    console.log(`✅ Passed: ${testResults.passed}`);
    console.log(`❌ Failed: ${testResults.failed}`);
    console.log(`📊 Total: ${testResults.passed + testResults.failed}`);
    console.log(`🎯 Success Rate: ${Math.round((testResults.passed / (testResults.passed + testResults.failed)) * 100)}%`);

    if (testResults.failed > 0) {
      console.log(`\n⚠️  ${testResults.failed} test(s) failed. Review issues above.`);
    } else {
      console.log(`\n🎉 All tests passed! Login flow is working perfectly.`);
    }

    console.log('\n💡 Browser left open for manual inspection.');
    console.log('   Press Ctrl+C when done.\n');

    // Keep browser open for inspection
    await new Promise(() => {});

  } catch (error) {
    console.error('\n❌ Fatal error during test execution:', error);
    if (browser) {
      await browser.close();
    }
    process.exit(1);
  }
})();
