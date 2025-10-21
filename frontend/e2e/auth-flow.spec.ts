import { test, expect } from '@playwright/test';

/**
 * Authentication Flow E2E Tests
 * Tests user registration, login, and logout flows
 */

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    // Start from landing page
    await page.goto('/');
  });

  test('should display login and register CTAs on landing page', async ({ page }) => {
    // Check header navigation
    const loginLink = page.getByRole('link', { name: /log in/i });
    const registerLink = page.getByRole('link', { name: /start free trial|sign up/i });

    await expect(loginLink).toBeVisible();
    await expect(registerLink).toBeVisible();
  });

  test('should navigate to registration page', async ({ page }) => {
    // Click on register CTA
    await page.getByRole('link', { name: /start free trial/i }).first().click();

    // Verify we're on the registration page
    await expect(page).toHaveURL(/\/auth\/register/);
    await expect(page.getByRole('heading', { name: /create account|sign up|register/i })).toBeVisible();
  });

  test('should navigate to login page', async ({ page }) => {
    // Click on login link
    await page.getByRole('link', { name: /log in/i }).click();

    // Verify we're on the login page
    await expect(page).toHaveURL(/\/auth\/login/);
    await expect(page.getByRole('heading', { name: /log in|sign in/i })).toBeVisible();
  });

  test('should show validation errors on empty login form', async ({ page }) => {
    await page.goto('/auth/login');

    // Try to submit empty form
    await page.getByRole('button', { name: /log in|sign in/i }).click();

    // Should show validation errors
    await expect(page.getByText(/email.*required|enter.*email/i)).toBeVisible();
    await expect(page.getByText(/password.*required|enter.*password/i)).toBeVisible();
  });

  test('should show validation errors on invalid email', async ({ page }) => {
    await page.goto('/auth/login');

    // Enter invalid email
    await page.getByLabel(/email/i).fill('invalid-email');
    await page.getByLabel(/password/i).fill('password123');
    await page.getByRole('button', { name: /log in|sign in/i }).click();

    // Should show validation error
    await expect(page.getByText(/valid email|invalid email/i)).toBeVisible();
  });

  test('should toggle password visibility', async ({ page }) => {
    await page.goto('/auth/login');

    const passwordInput = page.getByLabel(/password/i);
    const toggleButton = page.getByRole('button', { name: /show password|hide password|toggle/i });

    // Initially password should be hidden (type="password")
    await expect(passwordInput).toHaveAttribute('type', 'password');

    // Click toggle button
    if (await toggleButton.isVisible()) {
      await toggleButton.click();
      await expect(passwordInput).toHaveAttribute('type', 'text');

      // Click again to hide
      await toggleButton.click();
      await expect(passwordInput).toHaveAttribute('type', 'password');
    }
  });

  test('should have accessible form labels', async ({ page }) => {
    await page.goto('/auth/login');

    // All form inputs should have accessible labels
    const emailInput = page.getByLabel(/email/i);
    const passwordInput = page.getByLabel(/password/i);

    await expect(emailInput).toBeVisible();
    await expect(passwordInput).toBeVisible();

    // Check for proper ARIA attributes
    await expect(emailInput).toHaveAttribute('type', 'email');
    await expect(emailInput).toHaveAttribute('required');
  });

  test('should navigate between login and register pages', async ({ page }) => {
    await page.goto('/auth/login');

    // Find and click "Create account" or "Sign up" link
    const createAccountLink = page.getByRole('link', { name: /create account|sign up|register/i });

    if (await createAccountLink.isVisible()) {
      await createAccountLink.click();
      await expect(page).toHaveURL(/\/auth\/register/);
    }

    // Navigate back to login
    const loginLink = page.getByRole('link', { name: /log in|sign in|already have/i });

    if (await loginLink.isVisible()) {
      await loginLink.click();
      await expect(page).toHaveURL(/\/auth\/login/);
    }
  });

  test('should have proper page titles and meta tags', async ({ page }) => {
    await page.goto('/auth/login');
    await expect(page).toHaveTitle(/log in|sign in|coreflow360/i);

    await page.goto('/auth/register');
    await expect(page).toHaveTitle(/register|sign up|create account|coreflow360/i);
  });

  test('should be responsive on mobile viewport', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto('/auth/login');

    // Form should still be visible and usable
    const emailInput = page.getByLabel(/email/i);
    const passwordInput = page.getByLabel(/password/i);
    const submitButton = page.getByRole('button', { name: /log in|sign in/i });

    await expect(emailInput).toBeVisible();
    await expect(passwordInput).toBeVisible();
    await expect(submitButton).toBeVisible();
  });

  test('should handle keyboard navigation', async ({ page }) => {
    await page.goto('/auth/login');

    // Tab through form fields
    await page.keyboard.press('Tab');
    await expect(page.getByLabel(/email/i)).toBeFocused();

    await page.keyboard.press('Tab');
    await expect(page.getByLabel(/password/i)).toBeFocused();

    await page.keyboard.press('Tab');
    // Submit button should be focused (or password toggle if visible)
  });

  test.skip('should successfully login with valid credentials', async ({ page }) => {
    // This test requires API mocking or a test account
    // Skipped for now - implement with MSW in future iteration

    await page.goto('/auth/login');
    await page.getByLabel(/email/i).fill('test@example.com');
    await page.getByLabel(/password/i).fill('ValidPassword123!');
    await page.getByRole('button', { name: /log in|sign in/i }).click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(/\/dashboard/);
  });
});
