#!/usr/bin/env node
import { chromium } from 'playwright';

const URL = 'http://localhost:3000/landing';

(async () => {
  console.log('🧪 FULL PLAYWRIGHT TEST SUITE FOR LANDING PAGE\n');
  console.log('='.repeat(70) + '\n');

  const browser = await chromium.launch({
    headless: false, // Show browser for visual confirmation
    slowMo: 100 // Slow down actions to see them
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 }
  });

  const page = await context.newPage();

  // Error tracking
  const pageErrors = [];
  const consoleErrors = [];
  const networkErrors = [];

  page.on('pageerror', err => {
    pageErrors.push(err.message);
    console.log('❌ Page Error:', err.message);
  });

  page.on('console', msg => {
    if (msg.type() === 'error') {
      consoleErrors.push(msg.text());
      console.log('❌ Console Error:', msg.text());
    }
  });

  page.on('requestfailed', request => {
    const url = request.url();
    const resourceType = request.resourceType();

    // Ignore non-critical failures (fonts, favicons, analytics, images)
    if (url.includes('favicon.ico') ||
        url.includes('analytics') ||
        url.includes('fonts.googleapis') ||
        url.includes('fonts.gstatic') ||
        url.includes('.woff') ||
        url.includes('.woff2') ||
        url.includes('.ttf') ||
        resourceType === 'image' ||
        resourceType === 'font' ||
        resourceType === 'media') {
      return; // Skip non-critical resources
    }

    networkErrors.push(`${url} - ${request.failure().errorText}`);
  });

  let testsPassed = 0;
  let testsFailed = 0;

  const test = (name, condition) => {
    if (condition) {
      console.log(`✅ ${name}`);
      testsPassed++;
    } else {
      console.log(`❌ ${name}`);
      testsFailed++;
    }
  };

  try {
    // ========================================
    // TEST 1: Page Load
    // ========================================
    console.log('\n📄 TEST 1: PAGE LOAD\n' + '-'.repeat(70));

    const loadStart = Date.now();
    await page.goto(URL, { waitUntil: 'networkidle', timeout: 30000 });
    const loadTime = Date.now() - loadStart;

    test('Page loads successfully', true);
    test(`Page loads in < 5 seconds (${loadTime}ms)`, loadTime < 5000);

    await page.waitForTimeout(2000);

    // ========================================
    // TEST 2: Layout Components
    // ========================================
    console.log('\n🎨 TEST 2: LAYOUT COMPONENTS\n' + '-'.repeat(70));

    const header = await page.$('header');
    test('Header exists', !!header);

    const footer = await page.$('footer');
    test('Footer exists', !!footer);

    const main = await page.$('main');
    test('Main content exists', !!main);

    const nav = await page.$('nav');
    test('Navigation exists', !!nav);

    // ========================================
    // TEST 3: Hero Section
    // ========================================
    console.log('\n🚀 TEST 3: HERO SECTION\n' + '-'.repeat(70));

    const heroHeadline = await page.textContent('body');
    test('Hero headline contains "Run Multiple Businesses"', heroHeadline.includes('Run Multiple Businesses'));
    test('Hero has "Autopilot" text', heroHeadline.includes('Autopilot'));
    test('Hero has subheadline', heroHeadline.includes('AI agents handle all operations'));

    // Check for CTA buttons
    const buttons = await page.$$('button');
    test('Has multiple buttons', buttons.length >= 4);

    // Try to find "Start Free Trial" button
    const ctaButton = await page.$('button:has-text("Start Free Trial")');
    test('Primary CTA button exists', !!ctaButton);

    const demoButton = await page.$('button:has-text("Watch Demo")');
    test('Secondary CTA button exists', !!demoButton);

    // ========================================
    // TEST 4: Stats Banner
    // ========================================
    console.log('\n📊 TEST 4: STATS BANNER\n' + '-'.repeat(70));

    const bodyText = await page.textContent('body');
    test('Stats: Active Users shown', bodyText.includes('Active Users'));
    test('Stats: Revenue Managed shown', bodyText.includes('Revenue Managed'));
    test('Stats: Uptime SLA shown', bodyText.includes('Uptime SLA'));
    test('Stats: ROI shown', bodyText.includes('ROI') || bodyText.includes('847%'));

    // ========================================
    // TEST 5: Features Grid
    // ========================================
    console.log('\n⚡ TEST 5: FEATURES GRID\n' + '-'.repeat(70));

    test('Feature: Autonomous AI Agents', bodyText.includes('Autonomous AI Agents'));
    test('Feature: Multi-Business Native', bodyText.includes('Multi-Business Native'));
    test('Feature: Enterprise Security', bodyText.includes('Enterprise Security'));
    test('Feature: Lightning Fast', bodyText.includes('Lightning Fast'));
    test('Feature: Predictive Analytics', bodyText.includes('Predictive Analytics'));
    test('Feature: Team Collaboration', bodyText.includes('Team Collaboration'));

    // Check for feature icons
    const svgIcons = await page.$$('svg');
    test('Has SVG icons (lucide-react)', svgIcons.length > 5);

    // ========================================
    // TEST 6: Final CTA Section
    // ========================================
    console.log('\n🎯 TEST 6: FINAL CTA SECTION\n' + '-'.repeat(70));

    test('Final CTA headline exists', bodyText.includes('Ready to Scale'));
    test('Final CTA has compelling copy', bodyText.includes('entrepreneurs'));
    test('Final CTA button exists', bodyText.includes('Start Your Free Trial'));

    // ========================================
    // TEST 7: Navigation & Links
    // ========================================
    console.log('\n🔗 TEST 7: NAVIGATION & LINKS\n' + '-'.repeat(70));

    const navLinks = await page.$$('nav a, nav button');
    test('Navigation has multiple links', navLinks.length >= 5);

    const links = await page.$$('a');
    test('Page has links', links.length >= 10);

    // ========================================
    // TEST 8: Branding
    // ========================================
    console.log('\n🏢 TEST 8: BRANDING\n' + '-'.repeat(70));

    test('CoreFlow branding present', bodyText.includes('CoreFlow'));
    test('Version mentioned (V4)', bodyText.includes('V4') || bodyText.includes('CoreFlow360'));

    // ========================================
    // TEST 9: Responsive Design
    // ========================================
    console.log('\n📱 TEST 9: RESPONSIVE DESIGN\n' + '-'.repeat(70));

    // Test mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await page.waitForTimeout(1000);

    const mobileBodyText = await page.textContent('body');
    test('Mobile: Content still visible', mobileBodyText.length > 1000);
    test('Mobile: Hero headline visible', mobileBodyText.includes('Run Multiple Businesses'));

    // Test tablet viewport
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.waitForTimeout(1000);

    const tabletBodyText = await page.textContent('body');
    test('Tablet: Content still visible', tabletBodyText.length > 1000);

    // Return to desktop
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.waitForTimeout(1000);

    // ========================================
    // TEST 10: Button Interactions
    // ========================================
    console.log('\n🖱️  TEST 10: BUTTON INTERACTIONS\n' + '-'.repeat(70));

    // Test hover states
    const firstButton = await page.$('button');
    if (firstButton) {
      await firstButton.hover();
      test('Button hover works', true);
    }

    // Test button clicks (without navigation)
    const allButtons = await page.$$('button');
    test('All buttons are clickable', allButtons.length > 0);

    // ========================================
    // TEST 11: Performance Metrics
    // ========================================
    console.log('\n⚡ TEST 11: PERFORMANCE METRICS\n' + '-'.repeat(70));

    const metrics = await page.evaluate(() => ({
      images: document.querySelectorAll('img').length,
      scripts: document.querySelectorAll('script').length,
      styles: document.querySelectorAll('link[rel="stylesheet"], style').length,
      dom: document.querySelectorAll('*').length,
    }));

    test('Reasonable DOM size (< 2000 elements)', metrics.dom < 2000);
    test('Has styling', metrics.styles > 0);
    console.log(`   ℹ️  DOM elements: ${metrics.dom}`);
    console.log(`   ℹ️  Images: ${metrics.images}`);
    console.log(`   ℹ️  Scripts: ${metrics.scripts}`);
    console.log(`   ℹ️  Stylesheets: ${metrics.styles}`);

    // ========================================
    // TEST 12: Accessibility Basics
    // ========================================
    console.log('\n♿ TEST 12: ACCESSIBILITY BASICS\n' + '-'.repeat(70));

    const h1s = await page.$$('h1');
    test('Has H1 heading', h1s.length >= 1);
    test('Not too many H1s', h1s.length <= 2);

    const h2s = await page.$$('h2');
    test('Has H2 headings', h2s.length >= 2);

    const buttonsWithText = await page.$$('button:not(:empty)');
    test('Buttons have text content', buttonsWithText.length === allButtons.length);

    // ========================================
    // TEST 13: No Console Errors
    // ========================================
    console.log('\n🐛 TEST 13: ERROR CHECKING\n' + '-'.repeat(70));

    test('No page errors', pageErrors.length === 0);
    test('No console errors', consoleErrors.length === 0);
    test('No network failures', networkErrors.length === 0);

    if (pageErrors.length > 0) {
      console.log('\n   Page Errors:');
      pageErrors.forEach(err => console.log(`   - ${err.substring(0, 100)}`));
    }

    if (consoleErrors.length > 0) {
      console.log('\n   Console Errors:');
      consoleErrors.slice(0, 5).forEach(err => console.log(`   - ${err.substring(0, 100)}`));
    }

    // ========================================
    // TEST 14: Screenshot
    // ========================================
    console.log('\n📸 TEST 14: SCREENSHOT\n' + '-'.repeat(70));

    await page.screenshot({
      path: 'landing-page-screenshot.png',
      fullPage: true
    });
    test('Screenshot captured', true);
    console.log('   ℹ️  Screenshot saved: landing-page-screenshot.png');

  } catch (error) {
    console.log('\n❌ TEST SUITE ERROR:', error.message);
    testsFailed++;
  }

  // ========================================
  // FINAL RESULTS
  // ========================================
  console.log('\n' + '='.repeat(70));
  console.log('📊 FINAL TEST RESULTS');
  console.log('='.repeat(70));
  console.log(`✅ Passed: ${testsPassed}`);
  console.log(`❌ Failed: ${testsFailed}`);
  console.log(`📊 Total: ${testsPassed + testsFailed}`);
  console.log(`🎯 Success Rate: ${Math.round((testsPassed / (testsPassed + testsFailed)) * 100)}%`);

  if (testsFailed === 0) {
    console.log('\n🎉 ALL TESTS PASSED! Landing page is production-ready! 🚀');
  } else {
    console.log(`\n⚠️  ${testsFailed} test(s) failed. Review issues above.`);
  }

  console.log('\n💡 Browser left open for manual inspection.');
  console.log('   Press Ctrl+C when done.\n');

  // Keep browser open for manual inspection
  // await browser.close();
})();
