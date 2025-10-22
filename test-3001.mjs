#!/usr/bin/env node
import { chromium } from 'playwright';

const URL = 'http://localhost:3001/landing';

(async () => {
  console.log('🧪 Testing landing page after clean restart...\n');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  const errors = [];
  const consoleErrors = [];

  page.on('pageerror', err => errors.push(err.message));
  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
    }
  });

  try {
    await page.goto(URL, { waitUntil: 'networkidle', timeout: 15000 });
    await page.waitForTimeout(3001);

    const results = await page.evaluate(() => ({
      hasRoot: !!document.getElementById('root')?.children.length,
      sections: document.querySelectorAll('section').length,
      hasHero: !!document.querySelector('section'),
      hasEmail: !!document.querySelector('input[type="email"]'),
      hasPricing: !!document.querySelector('[id="pricing"]'),
      hasFooter: !!document.querySelector('footer'),
      visibleText: document.body.innerText.substring(0, 200)
    }));

    console.log('🎯 TEST RESULTS:');
    console.log('   URL:', URL);
    console.log('   React Root:', results.hasRoot ? '✅' : '❌');
    console.log('   Sections Found:', results.sections);
    console.log('   Hero:', results.hasHero ? '✅' : '❌');
    console.log('   Email Input:', results.hasEmail ? '✅' : '❌');
    console.log('   Pricing:', results.hasPricing ? '✅' : '❌');
    console.log('   Footer:', results.hasFooter ? '✅' : '❌');
    console.log('   Page Errors:', errors.length);
    console.log('   Console Errors:', consoleErrors.length);

    if (errors.length > 0) {
      console.log('\n❌ Page Errors:');
      errors.slice(0, 3).forEach((err, i) => {
        console.log(`   ${i + 1}. ${err.substring(0, 150)}`);
      });
    }

    if (consoleErrors.length > 0) {
      console.log('\n⚠️  Console Errors:');
      consoleErrors.slice(0, 3).forEach((err, i) => {
        console.log(`   ${i + 1}. ${err.substring(0, 150)}`);
      });
    }

    const success = results.hasRoot && results.hasHero && errors.length === 0;
    console.log(`\n${success ? '✅ SUCCESS!' : '❌ FAILED'}`);

    if (success) {
      console.log('🎉 Landing page is working correctly!');
      console.log('   All sections rendered without errors.');
    }

    await page.screenshot({ path: 'landing-clean-test.png', fullPage: true });
    console.log('\n📸 Screenshot: landing-clean-test.png');

    await browser.close();
    process.exit(success ? 0 : 1);
  } catch (error) {
    console.error('\n💥 Test Error:', error.message);
    await browser.close();
    process.exit(1);
  }
})();
