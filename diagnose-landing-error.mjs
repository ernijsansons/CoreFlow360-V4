#!/usr/bin/env node
import { chromium } from 'playwright';

const URL = 'http://localhost:3001/landing';

(async () => {
  console.log('🔍 Deep diagnostic of landing page error...\n');

  const browser = await chromium.launch({
    headless: false,
    devtools: true
  });
  const page = await browser.newPage();

  const errors = [];
  const consoleMessages = [];
  const reactErrors = [];

  // Capture all errors
  page.on('pageerror', err => {
    errors.push({
      message: err.message,
      stack: err.stack,
      name: err.name
    });
  });

  // Capture console messages
  page.on('console', msg => {
    const type = msg.type();
    const text = msg.text();
    consoleMessages.push({ type, text });

    // Look for React-specific errors
    if (type === 'error' && text.includes('React')) {
      reactErrors.push(text);
    }
  });

  console.log('📄 Loading page...');
  await page.goto(URL, { waitUntil: 'domcontentloaded', timeout: 15000 });

  // Wait for React to render (or fail)
  await page.waitForTimeout(5000);

  console.log('\n📊 PAGE ANALYSIS\n' + '='.repeat(50));

  // Check what rendered
  const rendered = await page.evaluate(() => {
    const root = document.getElementById('root');
    const sections = document.querySelectorAll('section');
    const hero = document.querySelector('[id*="hero"]') || sections[0];
    const features = document.querySelector('[id="features"]');
    const testimonials = document.querySelector('[id="testimonials"]');
    const pricing = document.querySelector('[id="pricing"]');
    const footer = document.querySelector('footer');

    return {
      hasRoot: !!root?.children.length,
      rootHTML: root?.innerHTML.substring(0, 200),
      sectionCount: sections.length,
      hasHero: !!hero,
      hasFeatures: !!features,
      hasTestimonials: !!testimonials,
      hasPricing: !!pricing,
      hasFooter: !!footer,
      bodyClasses: document.body.className,
    };
  });

  console.log('✓ Root element:', rendered.hasRoot ? '✅' : '❌');
  console.log('✓ Sections found:', rendered.sectionCount);
  console.log('✓ Hero:', rendered.hasHero ? '✅' : '❌');
  console.log('✓ Features:', rendered.hasFeatures ? '✅' : '❌');
  console.log('✓ Testimonials:', rendered.hasTestimonials ? '✅' : '❌');
  console.log('✓ Pricing:', rendered.hasPricing ? '✅' : '❌');
  console.log('✓ Footer:', rendered.hasFooter ? '✅' : '❌');

  console.log('\n🐛 ERRORS CAPTURED\n' + '='.repeat(50));
  console.log('Total page errors:', errors.length);
  console.log('Total console errors:', consoleMessages.filter(m => m.type === 'error').length);
  console.log('React-specific errors:', reactErrors.length);

  if (errors.length > 0) {
    console.log('\n📋 First Page Error:');
    console.log('Message:', errors[0].message);
    console.log('Name:', errors[0].name);
    console.log('\nStack trace:');
    console.log(errors[0].stack);
  }

  if (reactErrors.length > 0) {
    console.log('\n📋 First React Error:');
    console.log(reactErrors[0]);
  }

  // Check for specific component errors
  console.log('\n🔎 COMPONENT INSPECTION\n' + '='.repeat(50));

  const componentTest = await page.evaluate(() => {
    // Try to find error boundaries or error messages
    const errorBoundaries = document.querySelectorAll('[role="alert"]');
    const errorMessages = Array.from(document.querySelectorAll('*')).filter(el =>
      el.textContent?.includes('Objects are not valid') ||
      el.textContent?.includes('React child')
    );

    return {
      errorBoundaryCount: errorBoundaries.length,
      errorMessageCount: errorMessages.length,
      errorTexts: errorMessages.map(el => el.textContent?.substring(0, 100))
    };
  });

  console.log('Error boundaries found:', componentTest.errorBoundaryCount);
  console.log('Error messages in DOM:', componentTest.errorMessageCount);
  if (componentTest.errorTexts.length > 0) {
    console.log('Error texts:', componentTest.errorTexts);
  }

  // Keep browser open for manual inspection
  console.log('\n🔍 Browser left open for manual inspection');
  console.log('Press Ctrl+C to close when done\n');

  // Don't close browser automatically
  // await browser.close();
})();
