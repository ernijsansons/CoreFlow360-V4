#!/usr/bin/env node
import { chromium } from 'playwright';

const URL = 'http://localhost:3004/landing';

(async () => {
  console.log('✅ Testing FIXED landing page...\n');

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
    sections: document.querySelectorAll('section').length,
    hasHero: !!document.querySelector('section'),
    hasEmail: !!document.querySelector('input[type="email"]'),
    hasFeatures: !!document.querySelector('[id="features"]'),
    hasTestimonials: !!document.querySelector('[id="testimonials"]'),
    hasPricing: !!document.querySelector('[id="pricing"]'),
    hasFooter: !!document.querySelector('footer'),
    featureCards: document.querySelectorAll('[id="features"] .grid > div').length,
    testimonialCards: document.querySelectorAll('[id="testimonials"] .grid > div').length,
    pricingCards: document.querySelectorAll('[id="pricing"] .grid > div').length,
  }));

  console.log('📊 COMPONENT RENDERING\n' + '='.repeat(50));
  console.log('React Root:', results.hasRoot ? '✅' : '❌');
  console.log('Total Sections:', results.sections);
  console.log('Hero Section:', results.hasHero ? '✅' : '❌');
  console.log('Email Input:', results.hasEmail ? '✅' : '❌');
  console.log('Features Section:', results.hasFeatures ? '✅' : '❌', `(${results.featureCards} cards)`);
  console.log('Testimonials Section:', results.hasTestimonials ? '✅' : '❌', `(${results.testimonialCards} cards)`);
  console.log('Pricing Section:', results.hasPricing ? '✅' : '❌', `(${results.pricingCards} cards)`);
  console.log('Footer:', results.hasFooter ? '✅' : '❌');

  console.log('\n🐛 ERROR COUNT\n' + '='.repeat(50));
  console.log('Page Errors:', errors.length);
  console.log('Console Errors:', consoleErrors.length);

  if (errors.length > 0) {
    console.log('\n❌ First Error:', errors[0].substring(0, 200));
  }

  if (errors.length === 0 && results.hasFeatures && results.hasTestimonials && results.hasPricing && results.hasFooter) {
    console.log('\n🎉 SUCCESS! All sections render without errors!');
  } else {
    console.log('\n⚠️  Some sections still not rendering or errors present');
  }

  await browser.close();
})();
