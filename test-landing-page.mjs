#!/usr/bin/env node
/**
 * Landing Page Verification Script
 * Tests that the landing page loads without React errors
 */

import { chromium } from 'playwright';

async function testLandingPage() {
  console.log('[Test] Starting landing page verification...\n');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Capture console messages
  const consoleMessages = [];
  page.on('console', msg => {
    consoleMessages.push({
      type: msg.type(),
      text: msg.text()
    });
  });

  // Capture page errors
  const pageErrors = [];
  page.on('pageerror', error => {
    pageErrors.push({
      message: error.message,
      stack: error.stack
    });
  });

  try {
    console.log('[Test] Navigating to http://localhost:3003/landing...');
    await page.goto('http://localhost:3003/landing', {
      waitUntil: 'networkidle',
      timeout: 30000
    });

    console.log('[Test] ✓ Page loaded successfully\n');

    // Wait for React to mount
    await page.waitForTimeout(2000);

    // Check for React root rendering
    const hasReactRoot = await page.evaluate(() => {
      return document.querySelector('#root')?.children.length > 0;
    });

    console.log(`[Test] React root has content: ${hasReactRoot ? '✓ YES' : '✗ NO'}\n`);

    // Check for key landing page elements
    const heroExists = await page.locator('section').first().isVisible();
    console.log(`[Test] Hero section visible: ${heroExists ? '✓ YES' : '✗ NO'}`);

    // Check for errors
    const reactErrors = consoleMessages.filter(m =>
      m.type === 'error' &&
      (m.text.includes('React') || m.text.includes('useEffect') || m.text.includes('beginWork'))
    );

    console.log('\n[Test] Console Errors:', reactErrors.length);
    if (reactErrors.length > 0) {
      console.log('\nError Messages:');
      reactErrors.forEach((err, i) => {
        console.log(`  ${i + 1}. ${err.text}`);
      });
    }

    console.log('\n[Test] Page Errors:', pageErrors.length);
    if (pageErrors.length > 0) {
      console.log('\nPage Error Messages:');
      pageErrors.forEach((err, i) => {
        console.log(`  ${i + 1}. ${err.message}`);
        if (err.stack) {
          console.log(`     Stack: ${err.stack.split('\n')[0]}`);
        }
      });
    }

    // Test interactive elements
    console.log('\n[Test] Testing interactive elements...');

    // Check email input
    const emailInput = page.locator('input[type="email"]').first();
    const emailInputExists = await emailInput.isVisible();
    console.log(`  Email input: ${emailInputExists ? '✓ Found' : '✗ Missing'}`);

    // Check pricing cards
    const pricingCards = await page.locator('[id="pricing"]').isVisible();
    console.log(`  Pricing section: ${pricingCards ? '✓ Found' : '✗ Missing'}`);

    // Check theme toggle
    const themeToggle = await page.locator('button').filter({ hasText: /theme/i }).count();
    console.log(`  Theme toggle buttons: ${themeToggle > 0 ? '✓ Found' : '✗ Missing'}`);

    // Final verdict
    console.log('\n' + '='.repeat(60));
    if (pageErrors.length === 0 && reactErrors.length === 0 && hasReactRoot) {
      console.log('[Test] ✅ PASS - Landing page loaded successfully!');
    } else {
      console.log('[Test] ❌ FAIL - Landing page has errors');
    }
    console.log('='.repeat(60) + '\n');

  } catch (error) {
    console.error('[Test] ❌ Test failed with error:', error.message);
    throw error;
  } finally {
    await browser.close();
  }
}

// Run test
testLandingPage()
  .then(() => {
    console.log('[Test] Test completed');
    process.exit(0);
  })
  .catch(error => {
    console.error('[Test] Test failed:', error);
    process.exit(1);
  });
