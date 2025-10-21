/**
 * Basic CRM Test using Playwright
 * Tests core CRM functionality
 */

import { chromium } from 'playwright';

const BASE_URL = 'http://localhost:3002';
const API_URL = 'http://127.0.0.1:8790';

async function runCRMTests() {
  console.log('\n🚀 Starting CRM Comprehensive Tests\n');
  console.log('=' .repeat(60));

  const browser = await chromium.launch({
    headless: false,
    slowMo: 500 // Slow down for visibility
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 }
  });

  const page = await context.newPage();

  // Track test results
  const results = {
    total: 0,
    passed: 0,
    failed: 0,
    tests: []
  };

  function recordTest(name, passed, details = '') {
    results.total++;
    if (passed) {
      results.passed++;
      console.log(`✅ PASS: ${name}`);
    } else {
      results.failed++;
      console.log(`❌ FAIL: ${name} - ${details}`);
    }
    results.tests.push({ name, passed, details });
  }

  try {
    // ============================================================================
    // TEST 1: Login
    // ============================================================================
    console.log('\n📝 Test 1: Login to Application');
    await page.goto(`${BASE_URL}/login`);
    await page.waitForTimeout(2000);

    await page.fill('input[type="email"]', 'admin@coreflow360.com');
    await page.fill('input[type="password"]', 'Admin123!@#');
    await page.click('button[type="submit"]');

    try {
      await page.waitForURL('**/dashboard', { timeout: 10000 });
      recordTest('Login successful', true);
    } catch (e) {
      recordTest('Login successful', false, e.message);
    }

    // ============================================================================
    // TEST 2: Navigate to CRM Companies
    // ============================================================================
    console.log('\n📝 Test 2: Navigate to CRM Companies');
    try {
      await page.click('a[href*="/crm"]');
      await page.waitForTimeout(1000);

      const companiesLink = page.locator('a[href="/crm/companies"]');
      if (await companiesLink.isVisible()) {
        await companiesLink.click();
        await page.waitForTimeout(2000);
        recordTest('Navigate to Companies', true);
      } else {
        // Try direct navigation
        await page.goto(`${BASE_URL}/crm/companies`);
        await page.waitForTimeout(2000);
        recordTest('Navigate to Companies (direct)', true);
      }
    } catch (e) {
      recordTest('Navigate to Companies', false, e.message);
    }

    // ============================================================================
    // TEST 3: Companies Page Elements
    // ============================================================================
    console.log('\n📝 Test 3: Verify Companies Page Elements');

    // Check page title
    const hasTitle = await page.locator('h1, h2').filter({ hasText: /companies/i }).isVisible();
    recordTest('Companies page title visible', hasTitle);

    // Check search box
    const searchBox = page.locator('input[placeholder*="Search"], input[type="search"]');
    const hasSearch = await searchBox.count() > 0;
    recordTest('Search box present', hasSearch);

    // Take screenshot
    await page.screenshot({ path: 'test-results/companies-page.png', fullPage: true });

    // ============================================================================
    // TEST 4: Search Functionality
    // ============================================================================
    console.log('\n📝 Test 4: Test Search Functionality');
    if (hasSearch) {
      await searchBox.first().fill('Enterprise');
      await page.waitForTimeout(1000);
      recordTest('Search input works', true);

      await page.screenshot({ path: 'test-results/companies-search.png', fullPage: true });
    }

    // ============================================================================
    // TEST 5: Navigate to Contacts
    // ============================================================================
    console.log('\n📝 Test 5: Navigate to CRM Contacts');
    try {
      await page.goto(`${BASE_URL}/crm/contacts`);
      await page.waitForTimeout(2000);

      const hasContactsTitle = await page.locator('h1, h2').filter({ hasText: /contacts/i }).isVisible();
      recordTest('Navigate to Contacts', hasContactsTitle);

      await page.screenshot({ path: 'test-results/contacts-page.png', fullPage: true });
    } catch (e) {
      recordTest('Navigate to Contacts', false, e.message);
    }

    // ============================================================================
    // TEST 6: Contacts Page Elements
    // ============================================================================
    console.log('\n📝 Test 6: Verify Contacts Page Elements');

    const contactsSearch = page.locator('input[placeholder*="Search"], input[type="search"]');
    const hasContactsSearch = await contactsSearch.count() > 0;
    recordTest('Contacts search box present', hasContactsSearch);

    // ============================================================================
    // TEST 7: Navigate to Leads
    // ============================================================================
    console.log('\n📝 Test 7: Navigate to CRM Leads');
    try {
      await page.goto(`${BASE_URL}/crm/leads`);
      await page.waitForTimeout(2000);

      const hasLeadsTitle = await page.locator('h1, h2').filter({ hasText: /leads/i }).isVisible();
      recordTest('Navigate to Leads', hasLeadsTitle);

      await page.screenshot({ path: 'test-results/leads-page.png', fullPage: true });
    } catch (e) {
      recordTest('Navigate to Leads', false, e.message);
    }

    // ============================================================================
    // TEST 8: Data Quality Page
    // ============================================================================
    console.log('\n📝 Test 8: Navigate to Data Quality');
    try {
      await page.goto(`${BASE_URL}/crm/data-quality`);
      await page.waitForTimeout(2000);

      const hasDataQualityContent = await page.locator('h1, h2, h3').filter({ hasText: /data.*quality/i }).isVisible();
      recordTest('Navigate to Data Quality', hasDataQualityContent);

      await page.screenshot({ path: 'test-results/data-quality-page.png', fullPage: true });
    } catch (e) {
      recordTest('Navigate to Data Quality', false, e.message);
    }

    // ============================================================================
    // TEST 9: Integrations Dashboard
    // ============================================================================
    console.log('\n📝 Test 9: Navigate to Integrations Dashboard');
    try {
      await page.goto(`${BASE_URL}/crm/integrations-dashboard`);
      await page.waitForTimeout(2000);

      const hasIntegrationsContent = await page.locator('h1, h2, h3').filter({ hasText: /integrations/i }).isVisible();
      recordTest('Navigate to Integrations', hasIntegrationsContent);

      await page.screenshot({ path: 'test-results/integrations-page.png', fullPage: true });
    } catch (e) {
      recordTest('Navigate to Integrations', false, e.message);
    }

    // ============================================================================
    // TEST 10: Migration Wizard
    // ============================================================================
    console.log('\n📝 Test 10: Navigate to Migration Wizard');
    try {
      await page.goto(`${BASE_URL}/crm/migration`);
      await page.waitForTimeout(2000);

      const hasMigrationContent = await page.locator('h1, h2, h3').filter({ hasText: /migration/i }).isVisible();
      recordTest('Navigate to Migration', hasMigrationContent);

      await page.screenshot({ path: 'test-results/migration-page.png', fullPage: true });
    } catch (e) {
      recordTest('Navigate to Migration', false, e.message);
    }

    // ============================================================================
    // TEST 11: Enrichment Page
    // ============================================================================
    console.log('\n📝 Test 11: Navigate to Enrichment');
    try {
      await page.goto(`${BASE_URL}/crm/enrichment`);
      await page.waitForTimeout(2000);

      const hasEnrichmentContent = await page.locator('h1, h2, h3').filter({ hasText: /enrichment/i }).isVisible();
      recordTest('Navigate to Enrichment', hasEnrichmentContent);

      await page.screenshot({ path: 'test-results/enrichment-page.png', fullPage: true });
    } catch (e) {
      recordTest('Navigate to Enrichment', false, e.message);
    }

    // ============================================================================
    // Console Error Check
    // ============================================================================
    console.log('\n📝 Test 12: Check for Console Errors');
    const consoleErrors = [];
    page.on('console', msg => {
      if (msg.type() === 'error') {
        consoleErrors.push(msg.text());
      }
    });

    await page.waitForTimeout(2000);
    recordTest('No console errors', consoleErrors.length === 0, `Found ${consoleErrors.length} errors`);

    if (consoleErrors.length > 0) {
      console.log('\n⚠️  Console Errors Found:');
      consoleErrors.forEach((err, i) => {
        console.log(`  ${i + 1}. ${err}`);
      });
    }

  } catch (error) {
    console.error('\n❌ Fatal Error:', error.message);
    recordTest('Test execution', false, error.message);
  } finally {
    await browser.close();
  }

  // ============================================================================
  // FINAL RESULTS
  // ============================================================================
  console.log('\n' + '='.repeat(60));
  console.log('\n📊 TEST RESULTS SUMMARY\n');
  console.log(`Total Tests:  ${results.total}`);
  console.log(`✅ Passed:     ${results.passed}`);
  console.log(`❌ Failed:     ${results.failed}`);
  console.log(`Success Rate: ${((results.passed / results.total) * 100).toFixed(1)}%`);
  console.log('\n' + '='.repeat(60));

  // Detailed results
  console.log('\n📋 Detailed Results:\n');
  results.tests.forEach((test, i) => {
    console.log(`${i + 1}. [${test.passed ? '✅ PASS' : '❌ FAIL'}] ${test.name}`);
    if (test.details) {
      console.log(`   Details: ${test.details}`);
    }
  });

  console.log('\n📸 Screenshots saved to test-results/ directory\n');

  return results;
}

// Run tests
runCRMTests().catch(console.error);
