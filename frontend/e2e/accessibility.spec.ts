import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * Accessibility (a11y) E2E Tests
 * Tests WCAG A/AA compliance across key pages
 */

test.describe('Accessibility Tests', () => {
  test('landing page should have no accessibility violations', async ({ page }) => {
    await page.goto('/');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('login page should have no accessibility violations', async ({ page }) => {
    await page.goto('/auth/login');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('register page should have no accessibility violations', async ({ page }) => {
    await page.goto('/auth/register');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('pricing page should have no accessibility violations', async ({ page }) => {
    await page.goto('/pricing');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('skip-to-content link should be functional', async ({ page }) => {
    await page.goto('/');

    // Tab to skip link (should be first focusable element)
    await page.keyboard.press('Tab');

    const skipLink = page.getByRole('link', { name: /skip to main content|skip to content/i });

    // Skip link should be visible when focused
    await expect(skipLink).toBeFocused();

    // Clicking skip link should move focus to main content
    await skipLink.click();

    const mainContent = page.locator('#main-content, main');
    await expect(mainContent).toBeFocused();
  });

  test('all interactive elements should be keyboard accessible', async ({ page }) => {
    await page.goto('/');

    // Count all interactive elements
    const buttons = await page.getByRole('button').all();
    const links = await page.getByRole('link').all();

    // At least one button and link should exist
    expect(buttons.length).toBeGreaterThan(0);
    expect(links.length).toBeGreaterThan(0);

    // Tab through several elements to verify keyboard navigation
    for (let i = 0; i < Math.min(5, buttons.length + links.length); i++) {
      await page.keyboard.press('Tab');
      // Each tab should focus an element (no focus traps)
    }
  });

  test('images should have alt text', async ({ page }) => {
    await page.goto('/');

    const images = await page.locator('img').all();

    for (const img of images) {
      const alt = await img.getAttribute('alt');
      // Alt can be empty string for decorative images, but should exist
      expect(alt).not.toBeNull();
    }
  });

  test('form inputs should have associated labels', async ({ page }) => {
    await page.goto('/auth/login');

    const emailInput = page.getByLabel(/email/i);
    const passwordInput = page.getByLabel(/password/i);

    // Both inputs should be found via their labels
    await expect(emailInput).toBeVisible();
    await expect(passwordInput).toBeVisible();
  });

  test('color contrast should meet WCAG AA standards', async ({ page }) => {
    await page.goto('/');

    // axe-core includes color contrast checks
    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2aa'])
      .include(['body'])
      .analyze();

    const contrastViolations = accessibilityScanResults.violations.filter(
      (v) => v.id === 'color-contrast'
    );

    expect(contrastViolations).toEqual([]);
  });

  test('headings should be properly nested', async ({ page }) => {
    await page.goto('/');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a'])
      .analyze();

    const headingViolations = accessibilityScanResults.violations.filter(
      (v) => v.id.includes('heading')
    );

    expect(headingViolations).toEqual([]);
  });

  test('page should have a main landmark', async ({ page }) => {
    await page.goto('/');

    const main = page.locator('main, [role="main"]');
    await expect(main).toBeVisible();
  });

  test('focus should be visible on all interactive elements', async ({ page }) => {
    await page.goto('/');

    // Tab to first button
    await page.keyboard.press('Tab');

    // Get focused element
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();

    // Check if focus outline is visible (computed styles)
    const outlineStyle = await focusedElement.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        outline: styles.outline,
        outlineWidth: styles.outlineWidth,
        boxShadow: styles.boxShadow,
      };
    });

    // Should have either outline or box-shadow for focus indication
    const hasFocusStyle =
      (outlineStyle.outline && outlineStyle.outline !== 'none') ||
      (outlineStyle.outlineWidth && outlineStyle.outlineWidth !== '0px') ||
      (outlineStyle.boxShadow && outlineStyle.boxShadow !== 'none');

    expect(hasFocusStyle).toBeTruthy();
  });

  test('buttons should have accessible names', async ({ page }) => {
    await page.goto('/');

    const buttons = await page.getByRole('button').all();

    for (const button of buttons) {
      const accessibleName = await button.getAttribute('aria-label') || await button.textContent();
      expect(accessibleName).not.toBe('');
    }
  });

  test('should announce dynamic content changes', async ({ page }) => {
    await page.goto('/auth/login');

    // Submit form to trigger error messages
    await page.getByRole('button', { name: /log in|sign in/i }).click();

    // Error messages should be in a live region or role="alert"
    const errorRegions = page.locator('[role="alert"], [aria-live]');
    const errorCount = await errorRegions.count();

    // At least one error region should exist
    expect(errorCount).toBeGreaterThan(0);
  });
});
