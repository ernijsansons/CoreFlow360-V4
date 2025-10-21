#!/usr/bin/env node
import { chromium } from 'playwright';

const URL = 'http://localhost:3000/landing';

(async () => {
  console.log('🎨 Testing Marketing UI Components...\n');

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  const errors = [];
  page.on('pageerror', err => errors.push(err.message));

  await page.goto(URL, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(3000);

  const results = await page.evaluate(() => ({
    // Layout
    hasHeader: !!document.querySelector('header'),
    hasFooter: !!document.querySelector('footer'),
    hasMain: !!document.querySelector('main'),

    // Hero Section
    hasHeroHeadline: document.body.innerText.includes('Run Multiple Businesses'),
    hasCTAButtons: document.querySelectorAll('button').length,

    // Stats
    hasStats: document.body.innerText.includes('Active Users') && document.body.innerText.includes('Revenue Managed'),

    // Features
    hasFeatures: document.body.innerText.includes('Autonomous AI Agents'),
    featureCount: document.body.innerText.match(/Lightning Fast|Predictive Analytics|Team Collaboration/g)?.length || 0,

    // CTA Section
    hasCTA: document.body.innerText.includes('Ready to Scale'),

    // Navigation
    hasNavigation: !!document.querySelector('nav'),
    navLinks: document.querySelectorAll('nav a, nav button').length,

    // Content checks
    totalText: document.body.innerText.length,
    hasLogo: document.body.innerText.includes('CoreFlow'),
  }));

  console.log('📊 MARKETING UI ANALYSIS\n' + '='.repeat(50));
  console.log('✅ Layout Components:');
  console.log('  - Header:', results.hasHeader ? '✅' : '❌');
  console.log('  - Footer:', results.hasFooter ? '✅' : '❌');
  console.log('  - Main Content:', results.hasMain ? '✅' : '❌');
  console.log('  - Navigation:', results.hasNavigation ? '✅' : '❌', `(${results.navLinks} links)`);

  console.log('\n✅ Content Sections:');
  console.log('  - Hero Headline:', results.hasHeroHeadline ? '✅' : '❌');
  console.log('  - CTA Buttons:', results.hasCTAButtons, 'found');
  console.log('  - Stats Banner:', results.hasStats ? '✅' : '❌');
  console.log('  - Features Grid:', results.hasFeatures ? '✅' : '❌', `(${results.featureCount} features)`);
  console.log('  - Final CTA:', results.hasCTA ? '✅' : '❌');
  console.log('  - Logo/Branding:', results.hasLogo ? '✅' : '❌');

  console.log('\n🐛 Error Count:', errors.length);

  const allPassed = results.hasHeader && results.hasFooter && results.hasMain &&
                    results.hasHeroHeadline && results.hasStats && results.hasFeatures &&
                    results.hasCTA && errors.length === 0;

  if (allPassed) {
    console.log('\n🎉 SUCCESS! Complete marketing UI loaded perfectly!');
  } else {
    console.log('\n⚠️  Some components missing');
  }

  console.log('\nTotal content length:', results.totalText, 'characters');

  await browser.close();
})();
