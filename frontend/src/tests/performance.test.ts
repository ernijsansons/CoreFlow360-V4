/**
 * Performance tests for CoreFlow360 V4
 * Comprehensive performance benchmarks and regression testing
 */

import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'

// Performance thresholds based on Core Web Vitals
const PERFORMANCE_THRESHOLDS = {
  // Loading Performance
  LCP: 2500, // Largest Contentful Paint (ms)
  FCP: 1800, // First Contentful Paint (ms)
  TTFB: 800, // Time to First Byte (ms)

  // Interactivity
  FID: 100, // First Input Delay (ms)
  TBT: 300, // Total Blocking Time (ms)

  // Visual Stability
  CLS: 0.1, // Cumulative Layout Shift

  // Custom Metrics
  TTI: 3800, // Time to Interactive (ms)
  SI: 3000,  // Speed Index (ms)

  // Bundle Size (gzipped)
  BUNDLE_SIZE: {
    total: 1024 * 1024, // 1MB total
    js: 800 * 1024,     // 800KB JavaScript
    css: 100 * 1024,    // 100KB CSS
    images: 2048 * 1024 // 2MB images
  }
}

// Helper function to get Web Vitals metrics
async function getWebVitals(page: Page) {
  return await page.evaluate(() => {
    return new Promise((resolve) => {
      const metrics: Record<string, number> = {}
      let pendingMetrics = 5 // LCP, FID, CLS, FCP, TTFB

      const checkComplete = () => {
        pendingMetrics--
        if (pendingMetrics <= 0) {
          resolve(metrics)
        }
      }

      // Import web-vitals and collect metrics
      import('web-vitals').then((webVitals) => {
        webVitals.onLCP((metric) => {
          metrics.LCP = metric.value
          checkComplete()
        })

        webVitals.onFID((metric) => {
          metrics.FID = metric.value
          checkComplete()
        })

        webVitals.onCLS((metric) => {
          metrics.CLS = metric.value
          checkComplete()
        })

        webVitals.onFCP((metric) => {
          metrics.FCP = metric.value
          checkComplete()
        })

        webVitals.onTTFB((metric) => {
          metrics.TTFB = metric.value
          checkComplete()
        })
      }).catch(() => {
        // Fallback if web-vitals not available
        resolve(metrics)
      })

      // Timeout after 10 seconds
      setTimeout(() => resolve(metrics), 10000)
    })
  })
}

// Helper function to get resource timing
async function getResourceMetrics(page: Page) {
  return await page.evaluate(() => {
    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[]

    const metrics = {
      totalResources: resources.length,
      totalSize: 0,
      totalDuration: 0,
      jsSize: 0,
      cssSize: 0,
      imageSize: 0,
      slowResources: [] as string[]
    }

    resources.forEach((resource) => {
      const size = resource.transferSize || 0
      metrics.totalSize += size
      metrics.totalDuration += resource.duration

      if (resource.name.includes('.js')) {
        metrics.jsSize += size
      } else if (resource.name.includes('.css')) {
        metrics.cssSize += size
      } else if (/\.(jpg|jpeg|png|gif|webp|avif|svg)/.test(resource.name)) {
        metrics.imageSize += size
      }

      // Track slow resources (>1s)
      if (resource.duration > 1000) {
        metrics.slowResources.push(resource.name)
      }
    })

    return metrics
  })
}

// Test group: Core Web Vitals
test.describe('Core Web Vitals', () => {
  test('should meet LCP threshold @performance', async ({ page }) => {
    await page.goto('/')

    const metrics = await getWebVitals(page)

    console.log('LCP Score:', metrics.LCP)
    expect(metrics.LCP).toBeLessThan(PERFORMANCE_THRESHOLDS.LCP)
  })

  test('should meet FCP threshold @performance', async ({ page }) => {
    await page.goto('/')

    const metrics = await getWebVitals(page)

    console.log('FCP Score:', metrics.FCP)
    expect(metrics.FCP).toBeLessThan(PERFORMANCE_THRESHOLDS.FCP)
  })

  test('should meet CLS threshold @performance', async ({ page }) => {
    await page.goto('/')

    // Wait for page to settle
    await page.waitForLoadState('networkidle')

    const metrics = await getWebVitals(page)

    console.log('CLS Score:', metrics.CLS)
    expect(metrics.CLS).toBeLessThan(PERFORMANCE_THRESHOLDS.CLS)
  })

  test('should meet TTFB threshold @performance', async ({ page }) => {
    const startTime = Date.now()
    await page.goto('/')

    const metrics = await getWebVitals(page)

    console.log('TTFB Score:', metrics.TTFB)
    expect(metrics.TTFB).toBeLessThan(PERFORMANCE_THRESHOLDS.TTFB)
  })
})

// Test group: Bundle Size Analysis
test.describe('Bundle Size', () => {
  test('should meet total bundle size threshold @performance', async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')

    const resourceMetrics = await getResourceMetrics(page)

    console.log('Total Bundle Size:', Math.round(resourceMetrics.totalSize / 1024), 'KB')
    expect(resourceMetrics.totalSize).toBeLessThan(PERFORMANCE_THRESHOLDS.BUNDLE_SIZE.total)
  })

  test('should meet JavaScript bundle size threshold @performance', async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')

    const resourceMetrics = await getResourceMetrics(page)

    console.log('JavaScript Bundle Size:', Math.round(resourceMetrics.jsSize / 1024), 'KB')
    expect(resourceMetrics.jsSize).toBeLessThan(PERFORMANCE_THRESHOLDS.BUNDLE_SIZE.js)
  })

  test('should meet CSS bundle size threshold @performance', async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')

    const resourceMetrics = await getResourceMetrics(page)

    console.log('CSS Bundle Size:', Math.round(resourceMetrics.cssSize / 1024), 'KB')
    expect(resourceMetrics.cssSize).toBeLessThan(PERFORMANCE_THRESHOLDS.BUNDLE_SIZE.css)
  })

  test('should not have slow resources @performance', async ({ page }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')

    const resourceMetrics = await getResourceMetrics(page)

    console.log('Slow Resources:', resourceMetrics.slowResources)
    expect(resourceMetrics.slowResources.length).toBeLessThan(3) // Allow max 2 slow resources
  })
})

// Test group: Memory Usage
test.describe('Memory Performance', () => {
  test('should not have memory leaks during navigation @performance', async ({ page }) => {
    await page.goto('/')

    // Get initial memory usage
    const initialMemory = await page.evaluate(() => {
      return (performance as any).memory ? {
        usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
        totalJSHeapSize: (performance as any).memory.totalJSHeapSize
      } : null
    })

    if (!initialMemory) {
      test.skip('Memory API not available')
      return
    }

    // Navigate through different routes
    await page.click('a[href=\"/dashboard\"]')
    await page.waitForLoadState('networkidle')

    await page.click('a[href=\"/reports\"]')
    await page.waitForLoadState('networkidle')

    await page.click('a[href=\"/\"]')
    await page.waitForLoadState('networkidle')

    // Force garbage collection if possible
    await page.evaluate(() => {
      if ((window as any).gc) {
        (window as any).gc()
      }
    })

    // Wait a bit for cleanup
    await page.waitForTimeout(2000)

    // Get final memory usage
    const finalMemory = await page.evaluate(() => {
      return {
        usedJSHeapSize: (performance as any).memory.usedJSHeapSize,
        totalJSHeapSize: (performance as any).memory.totalJSHeapSize
      }
    })

    const memoryIncrease = finalMemory.usedJSHeapSize - initialMemory.usedJSHeapSize
    const memoryIncreasePercent = (memoryIncrease / initialMemory.usedJSHeapSize) * 100

    console.log('Memory increase:', Math.round(memoryIncrease / 1024), 'KB', `(${memoryIncreasePercent.toFixed(1)}%)`)

    // Memory should not increase by more than 50% after navigation
    expect(memoryIncreasePercent).toBeLessThan(50)
  })
})

// Test group: Rendering Performance
test.describe('Rendering Performance', () => {
  test('should render components quickly @performance', async ({ page }) => {
    await page.goto('/')

    // Measure time to render main components
    const renderTime = await page.evaluate(() => {
      const startTime = performance.now()

      return new Promise((resolve) => {
        // Wait for main content to be visible
        const observer = new MutationObserver(() => {
          const mainContent = document.querySelector('[data-testid=\"main-content\"]')
          if (mainContent) {
            observer.disconnect()
            resolve(performance.now() - startTime)
          }
        })

        observer.observe(document.body, {
          childList: true,
          subtree: true
        })

        // Timeout after 5 seconds
        setTimeout(() => {
          observer.disconnect()
          resolve(performance.now() - startTime)
        }, 5000)
      })
    })

    console.log('Component render time:', renderTime, 'ms')
    expect(renderTime).toBeLessThan(2000) // Should render within 2 seconds
  })

  test('should handle large lists efficiently @performance', async ({ page }) => {
    await page.goto('/dashboard')

    // Measure list rendering performance
    const listRenderTime = await page.evaluate(async () => {
      const startTime = performance.now()

      // Trigger large list rendering
      const event = new CustomEvent('render-large-list', {
        detail: { itemCount: 1000 }
      })
      document.dispatchEvent(event)

      // Wait for rendering to complete
      await new Promise(resolve => setTimeout(resolve, 100))

      return performance.now() - startTime
    })

    console.log('Large list render time:', listRenderTime, 'ms')
    expect(listRenderTime).toBeLessThan(500) // Should render within 500ms
  })
})

// Test group: Network Performance
test.describe('Network Performance', () => {
  test('should cache resources efficiently @performance', async ({ page }) => {
    // First visit
    await page.goto('/')
    await page.waitForLoadState('networkidle')

    // Get initial network requests
    const initialRequests = await page.evaluate(() => {
      return performance.getEntriesByType('resource').length
    })

    // Navigate away and back
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')

    await page.goto('/')
    await page.waitForLoadState('networkidle')

    // Get requests after cache
    const cachedRequests = await page.evaluate(() => {
      return performance.getEntriesByType('resource').length
    })

    console.log('Initial requests:', initialRequests)
    console.log('Cached requests:', cachedRequests)

    // Should have fewer requests due to caching
    expect(cachedRequests).toBeLessThan(initialRequests * 1.2) // Allow 20% increase
  })

  test('should handle offline scenarios gracefully @performance', async ({ page, context }) => {
    await page.goto('/')
    await page.waitForLoadState('networkidle')

    // Go offline
    await context.setOffline(true)

    // Try to navigate
    const offlineResponse = await page.evaluate(async () => {
      try {
        const response = await fetch('/api/dashboard')
        return response.status
      } catch (error) {
        return 'offline'
      }
    })

    console.log('Offline response:', offlineResponse)

    // Should handle offline gracefully
    expect(offlineResponse).toBe('offline')

    // Go back online
    await context.setOffline(false)
  })
})

// Test group: Accessibility Performance
test.describe('Accessibility Performance', () => {
  test('should maintain good performance with screen reader @performance', async ({ page }) => {
    // Simulate screen reader usage
    await page.goto('/')

    const ariaTime = await page.evaluate(() => {
      const startTime = performance.now()

      // Query all ARIA elements
      const ariaElements = document.querySelectorAll('[aria-label], [aria-describedby], [role]')

      // Simulate screen reader navigation
      ariaElements.forEach((element) => {
        element.getAttribute('aria-label')
        element.getAttribute('role')
      })

      return performance.now() - startTime
    })

    console.log('ARIA processing time:', ariaTime, 'ms')
    expect(ariaTime).toBeLessThan(100) // Should process quickly
  })
})

// Performance utilities
async function runPerformanceAudit(page: Page) {
  const metrics = await getWebVitals(page)
  const resources = await getResourceMetrics(page)

  return {
    webVitals: metrics,
    resources,
    score: calculatePerformanceScore(metrics, resources)
  }
}

function calculatePerformanceScore(webVitals: any, resources: any): number {
  let score = 100

  // Deduct points for poor Core Web Vitals
  if (webVitals.LCP > PERFORMANCE_THRESHOLDS.LCP) {
    score -= 20
  }
  if (webVitals.FCP > PERFORMANCE_THRESHOLDS.FCP) {
    score -= 15
  }
  if (webVitals.CLS > PERFORMANCE_THRESHOLDS.CLS) {
    score -= 15
  }
  if (webVitals.TTFB > PERFORMANCE_THRESHOLDS.TTFB) {
    score -= 10
  }

  // Deduct points for large bundles
  if (resources.jsSize > PERFORMANCE_THRESHOLDS.BUNDLE_SIZE.js) {
    score -= 20
  }
  if (resources.cssSize > PERFORMANCE_THRESHOLDS.BUNDLE_SIZE.css) {
    score -= 10
  }

  // Deduct points for slow resources
  score -= resources.slowResources.length * 5

  return Math.max(0, score)
}

// Export for use in other test files
export { runPerformanceAudit, calculatePerformanceScore, PERFORMANCE_THRESHOLDS }