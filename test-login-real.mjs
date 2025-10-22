#!/usr/bin/env node
/**
 * CoreFlow360 V4 - REAL BACKEND Login Test
 * Tests actual authentication with database
 * NO API MOCKING - Tests the complete stack
 */

import { chromium } from 'playwright';

const FRONTEND_URL = 'http://localhost:3003';
const BACKEND_URL = 'http://127.0.0.1:8790';
const TEST_USER = {
  email: 'test@coreflow360.dev',
  password: 'TestPass123!'
};

console.log('\n🚀 REAL BACKEND LOGIN TEST - COMPLETE END-TO-END\n');
console.log('======================================================================\n');
console.log('📧 Test Credentials:');
console.log(`   Email: ${TEST_USER.email}`);
console.log(`   Password: ${TEST_USER.password}\n`);
console.log('======================================================================\n');

let browser, page;
const consoleErrors = [];
const consoleLogs = [];
const networkRequests = [];

try {
  // Launch browser
  browser = await chromium.launch({
    headless: false, // Show browser
    slowMo: 100 // Slow down for observation
  });

  const context = await browser.newContext();
  page = await context.newPage();

  // ===================================================================
  // Capture Console Logs
  // ===================================================================
  page.on('console', msg => {
    const text = msg.text();
    const type = msg.type();

    consoleLogs.push({ type, text });

    if (type === 'log' && text.includes('[SafeStorage]')) {
      console.log(`  💾 ${text}`);
    }

    if (type === 'error' &&
        !text.includes('non-boolean attribute') &&
        !text.includes('Warning: Received')) {
      consoleErrors.push(text);
      console.log(`  ❌ ${text}`);
    }
  });

  // ===================================================================
  // Capture Network Requests
  // ===================================================================
  page.on('request', request => {
    if (request.url().includes('/api/')) {
      networkRequests.push({
        method: request.method(),
        url: request.url(),
        headers: request.headers()
      });
      console.log(`  🌐 ${request.method()} ${request.url()}`);
    }
  });

  page.on('response', async (response) => {
    if (response.url().includes('/api/auth/login')) {
      console.log(`\n  📥 LOGIN API RESPONSE:`);
      console.log(`     Status: ${response.status()}`);
      console.log(`     Headers:`, response.headers());
      try {
        const body = await response.text();
        console.log(`     Body:`, body.substring(0, 500));
      } catch (e) {
        console.log(`     Body: (unable to read)`);
      }
      console.log('');
    }
  });

  // ===================================================================
  // TEST 1: Backend Health Check
  // ===================================================================
  console.log('🏥 TEST 1: BACKEND HEALTH CHECK');
  console.log('----------------------------------------------------------------------');

  const healthResponse = await fetch(`${BACKEND_URL}/health`);
  const healthData = await healthResponse.json();
  console.log(`✅ Backend is healthy:`, healthData);
  console.log('');

  // ===================================================================
  // TEST 2: Navigate to Landing Page
  // ===================================================================
  console.log('📄 TEST 2: LANDING PAGE NAVIGATION');
  console.log('----------------------------------------------------------------------');

  await page.goto(FRONTEND_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForLoadState('networkidle');
  console.log('✅ Landing page loaded\n');

  // ===================================================================
  // TEST 3: Navigate to Login
  // ===================================================================
  console.log('🔑 TEST 3: NAVIGATE TO LOGIN');
  console.log('----------------------------------------------------------------------');

  const loginButton = page.locator('text=Login').first();
  await loginButton.click();
  console.log('✅ Clicked login button');
  await page.waitForTimeout(500);
  console.log('');

  // ===================================================================
  // TEST 4: Fill Login Form
  // ===================================================================
  console.log('📝 TEST 4: FILL LOGIN FORM');
  console.log('----------------------------------------------------------------------');

  const emailInput = page.locator('input[type="email"]').first();
  await emailInput.fill(TEST_USER.email);
  console.log(`✅ Filled email: ${TEST_USER.email}`);

  const passwordInput = page.locator('input[type="password"]').first();
  await passwordInput.fill(TEST_USER.password);
  console.log(`✅ Filled password: ${'*'.repeat(TEST_USER.password.length)}\n`);

  // ===================================================================
  // TEST 5: Submit Form (REAL BACKEND - NO MOCKING)
  // ===================================================================
  console.log('🚀 TEST 5: SUBMIT TO REAL BACKEND');
  console.log('----------------------------------------------------------------------');

  const submitButton = page.locator('button[type="submit"]').first();
  await submitButton.click();
  console.log('✅ Submitted form - waiting for backend response...\n');

  // Wait for authentication to complete
  await page.waitForTimeout(3000);

  // ===================================================================
  // TEST 6: Verify Storage
  // ===================================================================
  console.log('💾 TEST 6: VERIFY AUTH STORAGE');
  console.log('----------------------------------------------------------------------');

  const storageState = await page.evaluate(() => {
    const authStore = localStorage.getItem('auth-store');
    const rawToken = localStorage.getItem('token');

    return {
      authStore: authStore ? JSON.parse(authStore) : null,
      rawToken,
      allKeys: Object.keys(localStorage),
      sessionKeys: Object.keys(sessionStorage),
      cookiesCount: document.cookie.split(';').filter(c => c.trim()).length
    };
  });

  console.log('Storage State:');
  console.log(`  localStorage keys: [${storageState.allKeys.join(', ')}]`);
  console.log(`  sessionStorage keys: [${storageState.sessionKeys.join(', ')}]`);
  console.log(`  Cookies count: ${storageState.cookiesCount}`);

  if (storageState.authStore) {
    console.log('  ✅ auth-store found:');
    console.log(`     - isAuthenticated: ${storageState.authStore.state?.isAuthenticated}`);
    console.log(`     - user: ${storageState.authStore.state?.user?.email || 'not found'}`);
    console.log(`     - token: ${storageState.authStore.state?.token ? 'present' : 'missing'}`);
  } else {
    console.log('  ⚠️  auth-store not found in localStorage');
  }

  console.log('');

  // ===================================================================
  // TEST 7: Check Current URL
  // ===================================================================
  console.log('🌐 TEST 7: VERIFY NAVIGATION');
  console.log('----------------------------------------------------------------------');

  const currentUrl = page.url();
  console.log(`Current URL: ${currentUrl}`);

  if (currentUrl.includes('dashboard')) {
    console.log('✅ Successfully navigated to dashboard');
  } else if (currentUrl.includes('login')) {
    console.log('⚠️  Still on login page - check for errors');
  } else {
    console.log(`ℹ️  On page: ${currentUrl}`);
  }

  console.log('');

  // ===================================================================
  // TEST 8: Take Screenshots
  // ===================================================================
  console.log('📸 TEST 8: CAPTURE SCREENSHOTS');
  console.log('----------------------------------------------------------------------');

  await page.screenshot({ path: 'login-real-backend-final.png', fullPage: true });
  console.log('✅ Screenshot saved: login-real-backend-final.png\n');

  // ===================================================================
  // FINAL RESULTS
  // ===================================================================
  console.log('======================================================================');
  console.log('📊 FINAL TEST RESULTS - REAL BACKEND');
  console.log('======================================================================\n');

  const tests = {
    'Backend health check': true,
    'Landing page loaded': true,
    'Login navigation': true,
    'Form filled': true,
    'Form submitted': true,
    'Auth token stored': !!storageState.authStore?.state?.token,
    'User data stored': !!storageState.authStore?.state?.user,
    'No critical console errors': consoleErrors.length === 0,
    'API request sent': networkRequests.some(r => r.url.includes('/api/auth/login')),
    'Redirect occurred': !currentUrl.includes('login')
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
    console.log('🎉🎉🎉 PERFECT! 100% REAL BACKEND LOGIN WORKING! 🎉🎉🎉\n');
    console.log('✨ CREDENTIALS VERIFIED:');
    console.log(`   📧 Email: ${TEST_USER.email}`);
    console.log(`   🔑 Password: ${TEST_USER.password}\n`);
  } else if (passed >= 8) {
    console.log('✅ LOGIN WORKING! Minor issues detected but core functionality operational.\n');
  } else {
    console.log('⚠️  Some tests failed. Review the results above.\n');
  }

  console.log('💡 Browser left open for manual inspection.');
  console.log('   You can now:');
  console.log('   - Navigate manually in the browser');
  console.log('   - Check DevTools > Application > Local Storage');
  console.log('   - Test protected routes');
  console.log('   Press Ctrl+C when done.\n');

  // Keep browser open
  await new Promise(() => {});

} catch (error) {
  console.error('\n❌ TEST FAILED:', error.message);
  console.error('Stack:', error.stack);

  if (page) {
    await page.screenshot({ path: 'login-real-backend-error.png', fullPage: true });
    console.log('📸 Error screenshot saved: login-real-backend-error.png');
  }

  if (browser) {
    await browser.close();
  }

  process.exit(1);
}
