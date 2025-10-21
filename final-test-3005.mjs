#!/usr/bin/env node
import { chromium } from 'playwright';

const URL = 'http://localhost:3005/landing';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  const errors = [];
  page.on('pageerror', err => errors.push(err.message));

  await page.goto(URL, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(3000);

  const results = await page.evaluate(() => ({
    hasRoot: !!document.getElementById('root')?.children.length,
    hasHero: !!document.querySelector('section'),
    hasInput: !!document.querySelector('input[type="email"]'),
    hasPricing: !!document.querySelector('[id="pricing"]'),
    sections: document.querySelectorAll('section').length,
  }));

  console.log('\n🎯 FINAL TEST RESULTS:');
  console.log(`   URL: ${URL}`);
  console.log(`   React Root: ${results.hasRoot ? '✅' : '❌'}`);
  console.log(`   Hero Section: ${results.hasHero ? '✅' : '❌'}`);
  console.log(`   Email Input: ${results.hasInput ? '✅' : '❌'}`);
  console.log(`   Pricing Section: ${results.hasPricing ? '✅' : '❌'}`);
  console.log(`   Total Sections: ${results.sections}`);
  console.log(`   Page Errors: ${errors.length}`);

  if (errors.length > 0) {
    console.log('\n❌ Errors Found:');
    errors.slice(0, 3).forEach((err, i) => console.log(`   ${i + 1}. ${err.substring(0, 100)}`));
  }

  const success = results.hasRoot && results.hasHero && errors.length === 0;
  console.log(`\n${success ? '✅ SUCCESS!' : '❌ FAILED'}\n`);

  await page.screenshot({ path: 'landing-final.png', fullPage: true });
  console.log('📸 Screenshot: landing-final.png\n');

  await browser.close();
  process.exit(success ? 0 : 1);
})();
