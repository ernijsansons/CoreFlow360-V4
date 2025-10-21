#!/usr/bin/env node
import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  const allErrors = [];

  page.on('console', msg => {
    if (msg.type() === 'error') {
      allErrors.push(msg.text());
    }
  });

  await page.goto('http://localhost:3002/landing', { waitUntil: 'networkidle' });
  await page.waitForTimeout(5000);

  console.log(`Total errors: ${allErrors.length}\n`);

  if (allErrors.length > 0) {
    console.log('First 5 unique errors:\n');
    const unique = [...new Set(allErrors)];
    unique.slice(0, 5).forEach((err, i) => {
      console.log(`${i + 1}. ${err.substring(0, 300)}\n`);
    });
  }

  await browser.close();
})();
