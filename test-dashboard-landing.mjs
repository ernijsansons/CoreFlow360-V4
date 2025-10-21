#!/usr/bin/env node
import { chromium } from 'playwright';

const URL = 'http://localhost:3000/landing';

(async () => {
  console.log('🧪 Testing Dashboard-based landing page...\n');

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

  await page.goto(URL, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(3000);

  const results = await page.evaluate(() => ({
    hasRoot: !!document.getElementById('root')?.children.length,
    hasWelcomeBanner: !!document.querySelector('.bg-gradient-to-r'),
    hasDashboard: !!document.querySelector('[class*="Dashboard"]') || !!document.querySelectorAll('[class*="MetricsCard"]').length > 0,
    metricsCards: document.querySelectorAll('[class*="MetricsCard"]').length,
    charts: document.querySelectorAll('[class*="Chart"]').length,
    buttons: document.querySelectorAll('button').length,
    hasContent: document.body.innerText.length > 100,
  }));

  console.log('📊 PAGE ANALYSIS\n' + '='.repeat(50));
  console.log('React Root:', results.hasRoot ? '✅' : '❌');
  console.log('Welcome Banner:', results.hasWelcomeBanner ? '✅' : '❌');
  console.log('Dashboard Components:', results.hasDashboard ? '✅' : '❌');
  console.log('Metrics Cards:', results.metricsCards);
  console.log('Charts:', results.charts);
  console.log('Buttons:', results.buttons);
  console.log('Has Content:', results.hasContent ? '✅' : '❌');

  console.log('\n🐛 ERROR COUNT\n' + '='.repeat(50));
  console.log('Page Errors:', errors.length);
  console.log('Console Errors:', consoleErrors.length);

  if (errors.length > 0) {
    console.log('\n❌ First Error:', errors[0].substring(0, 200));
  }

  if (errors.length === 0 && results.hasWelcomeBanner && results.hasContent) {
    console.log('\n🎉 SUCCESS! Landing page with dashboard loads without errors!');
  } else {
    console.log('\n⚠️  Some issues detected');
  }

  await browser.close();
})();
