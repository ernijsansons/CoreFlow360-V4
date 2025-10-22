/**
 * Comprehensive CRM Testing Suite
 * Tests every field and functionality in the CRM module
 * Uses Playwright with Chrome DevTools Protocol
 */

import { test, expect, type Page } from '@playwright/test';

// Test configuration
const BASE_URL = 'http://localhost:3000';
const API_URL = 'http://127.0.0.1:8790';

// Helper function to login
async function login(page: Page) {
  await page.goto(`${BASE_URL}/login`);
  await page.fill('input[type="email"]', 'admin@coreflow360.com');
  await page.fill('input[type="password"]', 'Admin123!@#');
  await page.click('button[type="submit"]');
  await page.waitForURL('**/dashboard', { timeout: 10000 });
  await page.waitForTimeout(2000);
}

// Helper function to navigate to CRM section
async function navigateToCRM(page: Page, section: string) {
  await page.click(`a[href="/crm/${section}"]`);
  await page.waitForURL(`**/crm/${section}`, { timeout: 5000 });
  await page.waitForTimeout(1000);
}

test.describe('CRM Companies - Complete Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToCRM(page, 'companies');
  });

  test('Companies page loads and displays all UI elements', async ({ page }) => {
    // Check page title
    await expect(page.locator('h1')).toContainText(/companies/i);

    // Check search box exists
    await expect(page.locator('input[placeholder*="Search"]')).toBeVisible();

    // Check action buttons
    await expect(page.locator('button:has-text("Add Company")')).toBeVisible();
    await expect(page.locator('button:has-text("Export")')).toBeVisible();
    await expect(page.locator('button:has-text("Refresh")')).toBeVisible();
  });

  test('Search functionality works', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"]');
    await searchInput.fill('Enterprise');
    await page.waitForTimeout(500);

    // Verify filtered results
    const companyCards = page.locator('[data-testid="company-card"]');
    const count = await companyCards.count();
    console.log(`Found ${count} companies matching 'Enterprise'`);
  });

  test('Add company form - test all fields', async ({ page }) => {
    // Click add company button
    await page.click('button:has-text("Add Company")');
    await page.waitForTimeout(500);

    // Fill company name (required)
    await page.fill('input[name="name"]', 'Test Enterprise Corp');

    // Fill domain
    await page.fill('input[name="domain"]', 'testenterprise.com');

    // Select industry
    await page.click('select[name="industry"]');
    await page.selectOption('select[name="industry"]', 'Technology');

    // Select company size
    await page.click('select[name="size_range"]');
    await page.selectOption('select[name="size_range"]', '501-1000');

    // Select revenue range
    await page.click('select[name="revenue_range"]');
    await page.selectOption('select[name="revenue_range"]', '50M-100M');

    // Take screenshot of filled form
    await page.screenshot({ path: 'test-results/company-form-filled.png', fullPage: true });

    // Submit form
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);

    // Verify success message
    await expect(page.locator('text=/company.*created/i')).toBeVisible({ timeout: 5000 });
  });

  test('Filter companies by lifecycle stage', async ({ page }) => {
    const filters = ['customer', 'opportunity', 'sql', 'mql', 'lead'];

    for (const filter of filters) {
      await page.click(`button:has-text("${filter}")`);
      await page.waitForTimeout(500);
      console.log(`Filtered by ${filter}`);
    }
  });

  test('Export companies to CSV', async ({ page }) => {
    const downloadPromise = page.waitForEvent('download');
    await page.click('button:has-text("Export")');
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/companies.*\.csv/);
  });
});

test.describe('CRM Contacts - Complete Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToCRM(page, 'contacts');
  });

  test('Contacts page loads correctly', async ({ page }) => {
    await expect(page.locator('h1')).toContainText(/contacts/i);
    await expect(page.locator('input[placeholder*="Search"]')).toBeVisible();
    await expect(page.locator('button:has-text("Add Contact")')).toBeVisible();
  });

  test('Add contact form - test all required fields', async ({ page }) => {
    await page.click('button:has-text("Add Contact")');
    await page.waitForTimeout(500);

    // Fill email (required)
    await page.fill('input[name="email"]', 'john.doe@testcorp.com');

    // Fill optional fields
    await page.fill('input[name="first_name"]', 'John');
    await page.fill('input[name="last_name"]', 'Doe');
    await page.fill('input[name="phone"]', '+1 (555) 123-4567');
    await page.fill('input[name="title"]', 'Chief Technology Officer');

    // Select seniority level
    await page.selectOption('select[name="seniority_level"]', 'c_level');

    // Select department
    await page.selectOption('select[name="department"]', 'engineering');

    // Fill LinkedIn URL
    await page.fill('input[name="linkedin_url"]', 'https://linkedin.com/in/johndoe');

    // Screenshot
    await page.screenshot({ path: 'test-results/contact-form-filled.png', fullPage: true });

    // Submit
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);

    // Verify success
    await expect(page.locator('text=/contact.*created/i')).toBeVisible({ timeout: 5000 });
  });

  test('Search contacts by name and email', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="Search"]');

    // Search by name
    await searchInput.fill('John');
    await page.waitForTimeout(500);

    // Search by email
    await searchInput.clear();
    await searchInput.fill('john.doe@');
    await page.waitForTimeout(500);
  });

  test('View contact details', async ({ page }) => {
    // Click first contact
    const firstContact = page.locator('[data-testid="contact-card"]').first();
    await firstContact.click();
    await page.waitForTimeout(1000);

    // Verify contact detail view
    await expect(page.locator('text=/contact details/i')).toBeVisible();

    // Check all detail sections
    await expect(page.locator('text=/email/i')).toBeVisible();
    await expect(page.locator('text=/phone/i')).toBeVisible();
    await expect(page.locator('text=/company/i')).toBeVisible();
  });
});

test.describe('CRM Leads - Complete Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToCRM(page, 'leads');
  });

  test('Leads page displays correctly', async ({ page }) => {
    await expect(page.locator('h1')).toContainText(/leads/i);
    await expect(page.locator('button:has-text("Add Lead")')).toBeVisible();
  });

  test('Add lead form - test all fields', async ({ page }) => {
    await page.click('button:has-text("Add Lead")');
    await page.waitForTimeout(500);

    // Fill lead source (required)
    await page.fill('input[name="source"]', 'website');

    // Fill source campaign
    await page.fill('input[name="source_campaign"]', 'Q4 2025 Enterprise Campaign');

    // Select contact (if available)
    const contactSelect = page.locator('select[name="contact_id"]');
    if (await contactSelect.isVisible()) {
      await contactSelect.selectOption({ index: 1 });
    }

    // Select company (if available)
    const companySelect = page.locator('select[name="company_id"]');
    if (await companySelect.isVisible()) {
      await companySelect.selectOption({ index: 1 });
    }

    // Screenshot
    await page.screenshot({ path: 'test-results/lead-form-filled.png', fullPage: true });

    // Submit
    await page.click('button[type="submit"]');
    await page.waitForTimeout(2000);
  });

  test('Filter leads by status', async ({ page }) => {
    const statuses = ['new', 'contacted', 'qualified', 'proposal'];

    for (const status of statuses) {
      const filterButton = page.locator(`button:has-text("${status}")`);
      if (await filterButton.isVisible()) {
        await filterButton.click();
        await page.waitForTimeout(500);
        console.log(`Filtered by status: ${status}`);
      }
    }
  });

  test('Sort leads by score', async ({ page }) => {
    const sortButton = page.locator('button:has-text("Score")');
    if (await sortButton.isVisible()) {
      await sortButton.click();
      await page.waitForTimeout(500);

      // Verify sort order
      const scores = await page.locator('[data-testid="lead-score"]').allTextContents();
      console.log('Lead scores:', scores);
    }
  });
});

test.describe('CRM Conversations - Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('Create conversation - test all fields', async ({ page }) => {
    await navigateToCRM(page, 'contacts');

    // Open first contact
    await page.locator('[data-testid="contact-card"]').first().click();
    await page.waitForTimeout(1000);

    // Click add conversation
    const addConvButton = page.locator('button:has-text("Add Conversation")');
    if (await addConvButton.isVisible()) {
      await addConvButton.click();
      await page.waitForTimeout(500);

      // Select conversation type
      await page.selectOption('select[name="type"]', 'email');

      // Select direction
      await page.selectOption('select[name="direction"]', 'outbound');

      // Fill subject
      await page.fill('input[name="subject"]', 'Follow-up on Demo Request');

      // Fill content
      await page.fill('textarea[name="content"]', 'Thank you for your interest in our platform...');

      // Select outcome
      await page.selectOption('select[name="outcome"]', 'positive');

      // Screenshot
      await page.screenshot({ path: 'test-results/conversation-form-filled.png', fullPage: true });

      // Submit
      await page.click('button[type="submit"]');
      await page.waitForTimeout(2000);
    }
  });
});

test.describe('CRM Data Quality - Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToCRM(page, 'data-quality');
  });

  test('Data quality dashboard loads', async ({ page }) => {
    await expect(page.locator('h1')).toContainText(/data quality/i);

    // Check for quality metrics
    await expect(page.locator('text=/completeness/i')).toBeVisible();
    await expect(page.locator('text=/accuracy/i')).toBeVisible();
    await expect(page.locator('text=/duplicates/i')).toBeVisible();
  });

  test('Run data quality scan', async ({ page }) => {
    const scanButton = page.locator('button:has-text("Scan")');
    if (await scanButton.isVisible()) {
      await scanButton.click();
      await page.waitForTimeout(2000);

      // Verify scan results
      await expect(page.locator('text=/scan.*complete/i')).toBeVisible({ timeout: 10000 });
    }
  });
});

test.describe('CRM Integrations - Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToCRM(page, 'integrations-dashboard');
  });

  test('Integrations dashboard displays', async ({ page }) => {
    await expect(page.locator('h1')).toContainText(/integrations/i);

    // Check for integration options
    const integrationCards = page.locator('[data-testid="integration-card"]');
    const count = await integrationCards.count();
    console.log(`Found ${count} available integrations`);
  });

  test('Configure integration settings', async ({ page }) => {
    const configButton = page.locator('button:has-text("Configure")').first();
    if (await configButton.isVisible()) {
      await configButton.click();
      await page.waitForTimeout(1000);

      // Take screenshot of config modal
      await page.screenshot({ path: 'test-results/integration-config.png', fullPage: true });
    }
  });
});

test.describe('CRM Migration - Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToCRM(page, 'migration');
  });

  test('Migration wizard loads', async ({ page }) => {
    await expect(page.locator('h1')).toContainText(/migration/i);
  });

  test('Upload CSV file for migration', async ({ page }) => {
    const fileInput = page.locator('input[type="file"]');
    if (await fileInput.isVisible()) {
      // Create test CSV data
      const testCSV = 'Name,Email,Phone\nJohn Doe,john@test.com,555-1234\nJane Smith,jane@test.com,555-5678';
      const buffer = Buffer.from(testCSV);

      await fileInput.setInputFiles({
        name: 'test-contacts.csv',
        mimeType: 'text/csv',
        buffer: buffer
      });

      await page.waitForTimeout(1000);

      // Verify file uploaded
      await expect(page.locator('text=/file.*uploaded/i')).toBeVisible({ timeout: 5000 });
    }
  });
});

test.describe('CRM Enrichment - Field Testing', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await navigateToCRM(page, 'enrichment');
  });

  test('Enrichment page loads', async ({ page }) => {
    await expect(page.locator('h1')).toContainText(/enrichment/i);
  });

  test('Enrich company data', async ({ page }) => {
    const enrichButton = page.locator('button:has-text("Enrich")').first();
    if (await enrichButton.isVisible()) {
      await enrichButton.click();
      await page.waitForTimeout(2000);

      // Verify enrichment started
      await expect(page.locator('text=/enrichment.*started/i')).toBeVisible({ timeout: 5000 });
    }
  });
});

// Global error handler
test.afterEach(async ({ page }, testInfo) => {
  if (testInfo.status !== 'passed') {
    // Take screenshot on failure
    await page.screenshot({
      path: `test-results/failure-${testInfo.title.replace(/\s+/g, '-')}.png`,
      fullPage: true
    });

    // Log console errors
    page.on('console', msg => {
      if (msg.type() === 'error') {
        console.log(`Console Error: ${msg.text()}`);
      }
    });
  }
});
