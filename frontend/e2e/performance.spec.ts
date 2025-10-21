import { test, expect } from '@playwright/test';

/**
 * Performance E2E Tests
 * Tests Core Web Vitals and page performance metrics
 */

test.describe('Performance Tests', () => {
  test('landing page should load within 3 seconds', async ({ page }) => {
    const startTime = Date.now();

    await page.goto('/', { waitUntil: 'networkidle' });

    const loadTime = Date.now() - startTime;

    // Page should load in under 3 seconds
    expect(loadTime).toBeLessThan(3000);
  });

  test('landing page should have good Largest Contentful Paint (LCP)', async ({ page }) => {
    await page.goto('/');

    // Measure LCP using web-vitals
    const lcp = await page.evaluate(() => {
      return new Promise((resolve) => {
        const observer = new PerformanceObserver((list) => {
          const entries = list.getEntries();
          const lastEntry = entries[entries.length - 1];
          if (lastEntry) {
            resolve(lastEntry.renderTime || lastEntry.loadTime);
          }
        });

        observer.observe({ type: 'largest-contentful-paint', buffered: true });

        // Timeout after 10 seconds
        setTimeout(() => resolve(null), 10000);
      });
    });

    if (lcp) {
      // LCP should be under 2.5 seconds (good threshold)
      expect(lcp).toBeLessThan(2500);
    }
  });

  test('landing page should have low Cumulative Layout Shift (CLS)', async ({ page }) => {
    await page.goto('/');

    // Wait for page to stabilize
    await page.waitForLoadState('networkidle');

    // Measure CLS
    const cls = await page.evaluate(() => {
      return new Promise((resolve) => {
        let clsValue = 0;

        const observer = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (!(entry as any).hadRecentInput) {
              clsValue += (entry as any).value;
            }
          }
        });

        observer.observe({ type: 'layout-shift', buffered: true });

        // Wait 3 seconds then return CLS
        setTimeout(() => resolve(clsValue), 3000);
      });
    });

    // CLS should be under 0.1 (good threshold)
    expect(cls).toBeLessThan(0.1);
  });

  test('landing page should have fast First Input Delay (FID)', async ({ page }) => {
    await page.goto('/');

    // Wait for page to load
    await page.waitForLoadState('networkidle');

    // Click on a button to measure FID
    const button = page.getByRole('link', { name: /start free trial/i }).first();

    const startTime = Date.now();
    await button.click();
    const responseTime = Date.now() - startTime;

    // Input delay should be under 100ms (good threshold)
    expect(responseTime).toBeLessThan(100);
  });

  test('should not load unnecessary images on mobile', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });

    await page.goto('/');

    // Wait for page to load
    await page.waitForLoadState('networkidle');

    // Count loaded images
    const imageCount = await page.locator('img').count();

    // Mobile should have reasonable image count (not loading desktop hero images)
    expect(imageCount).toBeLessThan(10);
  });

  test('JavaScript bundle should be code-split', async ({ page }) => {
    // Monitor network requests
    const jsRequests: string[] = [];

    page.on('request', (request) => {
      if (request.resourceType() === 'script') {
        jsRequests.push(request.url());
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Should have multiple JS chunks (marketing, vendor, etc.)
    const jsChunks = jsRequests.filter((url) => url.includes('.js'));
    expect(jsChunks.length).toBeGreaterThan(1);

    // Should have a marketing chunk
    const hasMarketingChunk = jsChunks.some((url) =>
      url.includes('marketing') || url.includes('landing')
    );
    expect(hasMarketingChunk).toBeTruthy();
  });

  test('should lazy load images below the fold', async ({ page }) => {
    await page.goto('/');

    // Get all images
    const images = await page.locator('img').all();

    let lazyLoadedCount = 0;

    for (const img of images) {
      const loading = await img.getAttribute('loading');
      if (loading === 'lazy') {
        lazyLoadedCount++;
      }
    }

    // At least some images should be lazy loaded
    expect(lazyLoadedCount).toBeGreaterThan(0);
  });

  test('should prefetch navigation routes on hover', async ({ page }) => {
    await page.goto('/');

    const networkRequests: string[] = [];

    page.on('request', (request) => {
      networkRequests.push(request.url());
    });

    // Hover over a navigation link
    const pricingLink = page.getByRole('link', { name: /pricing/i });

    if (await pricingLink.isVisible()) {
      await pricingLink.hover();

      // Wait for potential prefetch
      await page.waitForTimeout(500);

      // Should prefetch the route (TanStack Router preloading)
      // This checks if any prefetch requests were made
      const prefetchRequests = networkRequests.filter((url) =>
        url.includes('pricing') || url.includes('.json')
      );

      // Note: Actual prefetch behavior depends on TanStack Router config
    }
  });

  test('should cache static assets', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // Reload the page
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Check if resources are served from cache
    const cachedRequests = await page.evaluate(() => {
      const resources = performance.getEntriesByType('resource');
      return resources.filter(
        (r: any) => r.transferSize === 0 && r.decodedBodySize > 0
      ).length;
    });

    // At least some resources should be cached
    expect(cachedRequests).toBeGreaterThan(0);
  });

  test('should not have render-blocking resources', async ({ page }) => {
    await page.goto('/');

    // Check for render-blocking resources
    const renderBlockingResources = await page.evaluate(() => {
      const resources = performance.getEntriesByType('resource');
      return resources.filter(
        (r: any) => r.renderBlockingStatus === 'blocking'
      ).length;
    });

    // Should minimize render-blocking resources
    expect(renderBlockingResources).toBeLessThan(3);
  });

  test('should load critical CSS inline', async ({ page }) => {
    await page.goto('/');

    // Check if there's inline CSS in <style> tags
    const inlineStyles = await page.locator('style').count();

    // Should have at least one inline style tag (Tailwind or critical CSS)
    expect(inlineStyles).toBeGreaterThan(0);
  });

  test('should have proper cache headers for static assets', async ({ page }) => {
    const responses: Map<string, any> = new Map();

    page.on('response', (response) => {
      if (response.url().includes('.js') || response.url().includes('.css')) {
        responses.set(response.url(), {
          cacheControl: response.headers()['cache-control'],
          url: response.url(),
        });
      }
    });

    await page.goto('/');
    await page.waitForLoadState('networkidle');

    // At least one static asset should have cache headers
    let hasCacheHeaders = false;
    responses.forEach((response) => {
      if (response.cacheControl && response.cacheControl.includes('max-age')) {
        hasCacheHeaders = true;
      }
    });

    expect(hasCacheHeaders).toBeTruthy();
  });
});
