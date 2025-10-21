#!/usr/bin/env node
/**
 * AGGRESSIVE DEBUG MODE - Capture everything from landing page
 */

import { chromium } from 'playwright';
import fs from 'fs';

async function aggressiveDebug() {
  console.log('🔥 AGGRESSIVE DEBUG MODE ACTIVATED\n');

  const browser = await chromium.launch({
    headless: false,  // Show browser window
    slowMo: 100  // Slow down for visibility
  });

  const context = await browser.newContext();
  const page = await context.newPage();

  // Capture EVERYTHING
  const allErrors = [];
  const allLogs = [];
  const allWarnings = [];

  page.on('console', msg => {
    const text = msg.text();
    const type = msg.type();

    if (type === 'error') {
      allErrors.push(text);
      console.log(`❌ ERROR: ${text.substring(0, 200)}`);
    } else if (type === 'warning') {
      allWarnings.push(text);
      console.log(`⚠️  WARN: ${text.substring(0, 200)}`);
    } else {
      allLogs.push(text);
    }
  });

  page.on('pageerror', error => {
    console.log(`💥 PAGE ERROR: ${error.message}`);
    console.log(`   Stack: ${error.stack?.split('\n')[0]}`);
    allErrors.push(`PAGE ERROR: ${error.message}\n${error.stack}`);
  });

  try {
    console.log('📡 Navigating to http://localhost:3003/landing...\n');

    await page.goto('http://localhost:3003/landing', {
      waitUntil: 'domcontentloaded',
      timeout: 10000
    });

    console.log('✅ Page loaded\n');

    // Wait a bit for React to try rendering
    await page.waitForTimeout(3000);

    // Take screenshot
    await page.screenshot({
      path: 'landing-page-debug.png',
      fullPage: true
    });
    console.log('📸 Screenshot saved: landing-page-debug.png\n');

    // Get the actual HTML
    const html = await page.content();
    fs.writeFileSync('landing-page-debug.html', html);
    console.log('💾 HTML saved: landing-page-debug.html\n');

    // Check React root
    const rootContent = await page.evaluate(() => {
      const root = document.getElementById('root');
      if (!root) return 'ROOT NOT FOUND';
      return {
        hasChildren: root.children.length > 0,
        childCount: root.children.length,
        innerHTML: root.innerHTML.substring(0, 500)
      };
    });

    console.log('🔍 React Root Status:', JSON.stringify(rootContent, null, 2));

    // Get the FIRST error in detail
    if (allErrors.length > 0) {
      console.log('\n🎯 FIRST ERROR (MOST IMPORTANT):');
      console.log(allErrors[0]);

      // Save all errors
      fs.writeFileSync('landing-errors.txt', allErrors.join('\n\n' + '='.repeat(80) + '\n\n'));
      console.log(`\n💾 All ${allErrors.length} errors saved to: landing-errors.txt`);
    } else {
      console.log('\n✅ NO ERRORS FOUND!');
    }

    // Check if any components rendered
    const componentCheck = await page.evaluate(() => {
      return {
        hasHero: !!document.querySelector('section'),
        hasInput: !!document.querySelector('input[type="email"]'),
        hasPricing: !!document.querySelector('[id="pricing"]'),
        hasFooter: !!document.querySelector('footer'),
        visibleSections: document.querySelectorAll('section').length
      };
    });

    console.log('\n🎨 Components Rendered:', JSON.stringify(componentCheck, null, 2));

    console.log('\n📊 Summary:');
    console.log(`   Errors: ${allErrors.length}`);
    console.log(`   Warnings: ${allWarnings.length}`);
    console.log(`   Logs: ${allLogs.length}`);
    console.log(`   Sections: ${componentCheck.visibleSections}`);

    // Keep browser open for manual inspection
    console.log('\n🔍 Browser window is open for manual inspection');
    console.log('   Press Ctrl+C to close\n');

    // Wait indefinitely
    await page.waitForTimeout(300000); // 5 minutes

  } catch (error) {
    console.error('\n💥 SCRIPT FAILED:', error.message);
  } finally {
    await browser.close();
  }
}

aggressiveDebug().catch(console.error);
