import { chromium } from 'playwright';

(async () => {
  console.log('🔍 DEV MODE VERIFICATION\n');

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const pageErrors = [];
  const consoleMessages = [];

  page.on('pageerror', error => {
    pageErrors.push(error.message);
    console.log('❌ PAGE ERROR:', error.message);
  });

  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleMessages.push(msg.text());
    }
  });

  try {
    console.log('Navigating to http://localhost:3003...\n');

    await page.goto('http://localhost:3003', {
      waitUntil: 'networkidle',
      timeout: 15000
    });

    await page.waitForTimeout(2000);

    const bodyText = await page.textContent('body');
    const mainCount = await page.locator('main').count();
    const h1Count = await page.locator('h1').count();
    const errorBoundaryVisible = bodyText?.includes('Something went wrong');

    console.log('='.repeat(70));
    console.log('📊 DEV MODE RESULTS:\n');
    console.log(`  Body Length: ${bodyText?.length || 0} characters`);
    console.log(`  <main> elements: ${mainCount}`);
    console.log(`  <h1> elements: ${h1Count}`);
    console.log(`  Error Boundary Showing: ${errorBoundaryVisible}`);
    console.log(`  Page Errors: ${pageErrors.length}`);
    console.log(`  Console Errors: ${consoleMessages.length}`);
    console.log('='.repeat(70));

    if (bodyText && bodyText.length > 500 && !errorBoundaryVisible && pageErrors.length === 0) {
      console.log('\n✅✅✅ SUCCESS! Dev mode works perfectly! ✅✅✅');
      console.log(`\nFirst 200 chars: ${bodyText.substring(0, 200)}...`);
    } else if (errorBoundaryVisible) {
      console.log('\n❌ FAILED: Error Boundary still showing in dev mode');
    } else if (pageErrors.length > 0) {
      console.log('\n❌ FAILED: JavaScript errors detected');
      pageErrors.forEach((err, i) => {
        console.log(`  ${i + 1}. ${err}`);
      });
    } else {
      console.log('\n❌ FAILED: Page appears blank or incomplete');
    }

  } catch (error) {
    console.error('\n❌ Test Failed:', error.message);
  }

  await browser.close();
})();
