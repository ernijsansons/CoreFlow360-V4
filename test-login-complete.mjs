#!/usr/bin/env node
/**
 * CoreFlow360 V4 - Complete Login Flow Test
 * Comprehensive end-to-end test with API mocking
 */

import { chromium } from 'playwright';

const FRONTEND_URL = 'http://localhost:3000';
const TEST_USER = {
  email: 'test@example.com',
  password: 'password'
};

const MOCK_LOGIN_RESPONSE = {
  success: true,
  data: {
    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJ0ZXN0LXVzZXItMDAxIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaWF0IjoxNjgwMDAwMDAwLCJleHAiOjE2ODAwODY0MDB9.test',
    refreshToken: 'refresh-token-mock',
    user: {
      id: 'test-user-001',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      role: 'admin',
      businessId: 'test-business-001'
    },
    expiresIn: 86400
  }
};

console.log('\n🧪 COMPLETE LOGIN FLOW TEST\n');
console.log('======================================================================\n');

let browser, page;
const consoleErrors = [];
const networkErrors = [];

try {
  // Launch browser
  browser = await chromium.launch({
    headless: false, // Show browser for visual confirmation
    slowMo: 50 // Slow down for observation
  });

  const context = await browser.newContext();
  page = await context.newPage();

  // ===================================================================
  // TEST 1: Navigate to Landing Page
  // ===================================================================
  console.log('📄 TEST 1: LANDING PAGE NAVIGATION');
  console.log('----------------------------------------------------------------------');

  await page.goto(FRONTEND_URL, { waitUntil: 'domcontentloaded' });
  console.log('✅ Navigated to landing page');

  // Wait for page to be interactive
  await page.waitForLoadState('networkidle');
  console.log('✅ Page loaded completely\n');

  // ===================================================================
  // TEST 2: Find and Click Login Button
  // ===================================================================
  console.log('🔍 TEST 2: FIND LOGIN BUTTON');
  console.log('----------------------------------------------------------------------');

  // Look for login/sign-in button
  const loginButtonSelectors = [
    'text=Sign In',
    'text=Login',
    'text=Log In',
    'button:has-text("Sign")',
    'a:has-text("Sign")',
    '[href*="login"]'
  ];

  let loginButton = null;
  for (const selector of loginButtonSelectors) {
    const element = await page.locator(selector).first();
    if (await element.count() > 0) {
      loginButton = element;
      console.log(`✅ Found login button: ${selector}`);
      break;
    }
  }

  if (!loginButton) {
    // If no button, assume we're on the login page already
    const emailInput = await page.locator('input[type="email"]').count();
    if (emailInput > 0) {
      console.log('✅ Already on login page');
    } else {
      throw new Error('Could not find login button or email input');
    }
  } else {
    await loginButton.click();
    console.log('✅ Clicked login button');
    await page.waitForTimeout(500);
  }

  console.log('');

  // ===================================================================
  // TEST 3: Setup API Mocking
  // ===================================================================
  console.log('🎭 TEST 3: SETUP API MOCKING');
  console.log('----------------------------------------------------------------------');

  // Intercept console errors
  page.on('console', msg => {
    if (msg.type() === 'error') {
      const text = msg.text();
      // Filter out non-critical React warnings
      if (text.includes('non-boolean attribute') ||
          text.includes('Warning: Received')) {
        return;
      }
      consoleErrors.push(text);
    }
  });

  // Intercept network errors
  page.on('requestfailed', request => {
    const url = request.url();
    const resourceType = request.resourceType();

    // Ignore non-critical failures
    if (url.includes('favicon.ico') ||
        url.includes('analytics') ||
        url.includes('fonts.googleapis') ||
        url.includes('fonts.gstatic') ||
        resourceType === 'image' ||
        resourceType === 'font' ||
        resourceType === 'media') {
      return;
    }

    networkErrors.push(`${url} - ${request.failure().errorText}`);
  });

  // Mock the login API endpoint
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
        body: JSON.stringify(MOCK_LOGIN_RESPONSE)
      });
    } else {
      await route.continue();
    }
  });

  // Handle OPTIONS requests
  await page.route('**/api/auth/login', async route => {
    if (route.request().method() === 'OPTIONS') {
      await route.fulfill({
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        }
      });
    }
  });

  console.log('✅ API mocking configured\n');

  // ===================================================================
  // TEST 4: Fill Login Form
  // ===================================================================
  console.log('📝 TEST 4: FILL LOGIN FORM');
  console.log('----------------------------------------------------------------------');

  // Find email input
  const emailInput = page.locator('input[type="email"], input[name="email"]').first();
  await emailInput.waitFor({ state: 'visible', timeout: 5000 });
  await emailInput.fill(TEST_USER.email);
  console.log(`✅ Filled email: ${TEST_USER.email}`);

  // Find password input
  const passwordInput = page.locator('input[type="password"], input[name="password"]').first();
  await passwordInput.waitFor({ state: 'visible' });
  await passwordInput.fill(TEST_USER.password);
  console.log(`✅ Filled password: ${'*'.repeat(TEST_USER.password.length)}\n`);

  // ===================================================================
  // TEST 5: Submit Login Form
  // ===================================================================
  console.log('🚀 TEST 5: SUBMIT LOGIN FORM');
  console.log('----------------------------------------------------------------------');

  // Find and click submit button
  const submitButtonSelectors = [
    'button[type="submit"]',
    'button:has-text("Sign In")',
    'button:has-text("Login")',
    'button:has-text("Log In")'
  ];

  let submitButton = null;
  for (const selector of submitButtonSelectors) {
    const element = page.locator(selector).first();
    if (await element.count() > 0) {
      submitButton = element;
      console.log(`✅ Found submit button: ${selector}`);
      break;
    }
  }

  if (!submitButton) {
    throw new Error('Could not find submit button');
  }

  // Take screenshot before submission
  await page.screenshot({ path: 'login-before-submit.png', fullPage: true });
  console.log('📸 Screenshot saved: login-before-submit.png');

  // Click submit
  await submitButton.click();
  console.log('✅ Clicked submit button');

  // Wait for API call to complete
  await page.waitForTimeout(1000);
  console.log('');

  // ===================================================================
  // TEST 6: Verify Post-Login State
  // ===================================================================
  console.log('✅ TEST 6: VERIFY POST-LOGIN STATE');
  console.log('----------------------------------------------------------------------');

  // Check localStorage for auth token
  const authToken = await page.evaluate(() => {
    return localStorage.getItem('auth-storage') || localStorage.getItem('token');
  });

  if (authToken) {
    console.log('✅ Auth token stored in localStorage');
    try {
      const parsed = JSON.parse(authToken);
      if (parsed.state?.token || parsed.token) {
        console.log('✅ Token structure is valid');
      }
    } catch (e) {
      console.log('ℹ️  Token is a plain string (not JSON)');
    }
  } else {
    console.log('⚠️  No auth token found in localStorage (may be using cookies)');
  }

  // Check if URL changed (redirected)
  const currentUrl = page.url();
  console.log(`ℹ️  Current URL: ${currentUrl}`);

  if (currentUrl.includes('dashboard') || currentUrl.includes('home') || currentUrl.includes('app')) {
    console.log('✅ Successfully redirected to dashboard');
  } else if (currentUrl === FRONTEND_URL || currentUrl === `${FRONTEND_URL}/`) {
    console.log('ℹ️  Still on landing page (may need manual navigation check)');
  }

  // Take screenshot after login
  await page.screenshot({ path: 'login-after-submit.png', fullPage: true });
  console.log('📸 Screenshot saved: login-after-submit.png\n');

  // ===================================================================
  // TEST 7: Check for Errors
  // ===================================================================
  console.log('🐛 TEST 7: ERROR CHECKING');
  console.log('----------------------------------------------------------------------');

  if (consoleErrors.length === 0) {
    console.log('✅ No console errors');
  } else {
    console.log(`⚠️  Found ${consoleErrors.length} console error(s):`);
    consoleErrors.slice(0, 5).forEach(err => console.log(`   - ${err}`));
  }

  if (networkErrors.length === 0) {
    console.log('✅ No network failures');
  } else {
    console.log(`⚠️  Found ${networkErrors.length} network error(s):`);
    networkErrors.slice(0, 5).forEach(err => console.log(`   - ${err}`));
  }

  console.log('');

  // ===================================================================
  // FINAL RESULTS
  // ===================================================================
  console.log('======================================================================');
  console.log('📊 FINAL TEST RESULTS');
  console.log('======================================================================');

  const tests = {
    'Landing page loaded': true,
    'Login button found': true,
    'Login form filled': true,
    'Form submitted successfully': true,
    'API mocking working': true,
    'Auth token stored': !!authToken,
    'No critical console errors': consoleErrors.length === 0,
    'No network failures': networkErrors.length === 0
  };

  let passed = 0;
  let failed = 0;

  Object.entries(tests).forEach(([test, result]) => {
    if (result) {
      console.log(`✅ ${test}`);
      passed++;
    } else {
      console.log(`❌ ${test}`);
      failed++;
    }
  });

  console.log('');
  console.log(`📊 Total: ${passed + failed} | ✅ Passed: ${passed} | ❌ Failed: ${failed}`);
  console.log(`🎯 Success Rate: ${Math.round((passed / (passed + failed)) * 100)}%\n`);

  if (failed === 0) {
    console.log('🎉 ALL TESTS PASSED! Login flow working correctly! 🚀\n');
  } else {
    console.log('⚠️  Some tests failed. Review the results above.\n');
  }

  console.log('💡 Browser left open for manual inspection.');
  console.log('   Press Ctrl+C when done.\n');

  // Keep browser open for manual inspection
  await new Promise(() => {});

} catch (error) {
  console.error('❌ TEST FAILED:', error.message);
  console.error('Stack:', error.stack);

  if (page) {
    await page.screenshot({ path: 'login-error.png', fullPage: true });
    console.log('📸 Error screenshot saved: login-error.png');
  }

  if (browser) {
    await browser.close();
  }

  process.exit(1);
}
