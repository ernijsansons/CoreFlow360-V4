import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

// Test data and selectors
const LANDING_PAGE_URL = '/landing'
const SELECTORS = {
  hero: '[data-testid="hero-section"]',
  features: '[data-testid="features-section"]',
  testimonials: '[data-testid="testimonials-section"]',
  pricing: '[data-testid="pricing-section"]',
  footer: '[data-testid="footer-section"]',
  ctaButton: '[data-testid="cta-button"]',
  pricingToggle: '[data-testid="pricing-toggle"]',
  emailInput: '[data-testid="email-input"]',
  featureIcon: '[data-testid="feature-icon"]',
  testimonialCard: '[data-testid="testimonial-card"]',
  pricingCard: '[data-testid="pricing-card"]'
}

// Helper function to check for React errors
async function checkForReactErrors(page: Page): Promise<string[]> {
  const errors: string[] = []
  
  page.on('console', msg => {
    if (msg.type() === 'error') {
      const text = msg.text()
      if (text.includes('Objects are not valid as a React child') ||
          text.includes('Cannot read properties of null') ||
          text.includes('React') ||
          text.includes('hydration')) {
        errors.push(text)
      }
    }
  })
  
  return errors
}

// Helper function to measure performance
async function measurePerformance(page: Page) {
  const performanceMetrics = await page.evaluate(() => {
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming
    const paint = performance.getEntriesByType('paint')
    
    return {
      loadTime: navigation.loadEventEnd - navigation.loadEventStart,
      domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
      firstContentfulPaint: paint.find(p => p.name === 'first-contentful-paint')?.startTime || 0,
      largestContentfulPaint: 0 // Would need to observe LCP
    }
  })
  
  return performanceMetrics
}

test.describe('Landing Page - Core Rendering', () => {
  test('should load landing page without errors', async ({ page }) => {
    const reactErrors: string[] = []
    
    // Listen for React errors
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().includes('React')) {
        reactErrors.push(msg.text())
      }
    })
    
    await page.goto(LANDING_PAGE_URL)
    
    // Wait for page to fully load
    await page.waitForLoadState('networkidle')
    
    // Check for React errors
    expect(reactErrors).toHaveLength(0)
    
    // Verify page title
    await expect(page).toHaveTitle(/CoreFlow360/)
    
    // Verify main sections are present
    await expect(page.locator('main, [role="main"]')).toBeVisible()
  })

  test('should render all main sections', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Check for main sections (using semantic selectors or fallback to text content)
    const sections = [
      'hero', 'features', 'testimonials', 'pricing', 'footer'
    ]
    
    for (const section of sections) {
      // Try multiple selectors for each section
      const selectors = [
        `[data-testid="${section}-section"]`,
        `#${section}`,
        `[id*="${section}"]`,
        `section:has-text("${section}")`
      ]
      
      let found = false
      for (const selector of selectors) {
        if (await page.locator(selector).count() > 0) {
          found = true
          break
        }
      }
      
      // If not found by selectors, check for section content
      if (!found) {
        const sectionContent = await page.textContent('body')
        expect(sectionContent).toContain(section)
      }
    }
  })

  test('should render Heroicons as SVG elements', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Check that icons are rendered as SVG elements, not objects
    const svgIcons = page.locator('svg')
    const iconCount = await svgIcons.count()
    
    expect(iconCount).toBeGreaterThan(0)
    
    // Verify SVG elements have proper attributes
    for (let i = 0; i < Math.min(iconCount, 5); i++) {
      const svg = svgIcons.nth(i)
      await expect(svg).toBeVisible()
      await expect(svg).toHaveAttribute('viewBox')
    }
  })

  test('should load all images without errors', async ({ page }) => {
    const failedImages: string[] = []
    
    page.on('response', response => {
      if (response.url().includes('.png') || response.url().includes('.jpg') || response.url().includes('.svg')) {
        if (response.status() >= 400) {
          failedImages.push(response.url())
        }
      }
    })
    
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Wait for all images to load
    await page.waitForFunction(() => {
      const images = Array.from(document.querySelectorAll('img'))
      return images.every(img => img.complete)
    }, { timeout: 10000 })
    
    expect(failedImages).toHaveLength(0)
  })
})

test.describe('Landing Page - Interactivity', () => {
  test('should have clickable CTA buttons', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Find CTA buttons (try multiple selectors)
    const ctaSelectors = [
      'button:has-text("Get Started")',
      'button:has-text("Start Free Trial")',
      'button:has-text("Sign Up")',
      '[data-testid="cta-button"]',
      'a[href*="signup"]',
      'a[href*="register"]'
    ]
    
    let ctaFound = false
    for (const selector of ctaSelectors) {
      const buttons = page.locator(selector)
      if (await buttons.count() > 0) {
        const firstButton = buttons.first()
        await expect(firstButton).toBeVisible()
        await expect(firstButton).toBeEnabled()
        ctaFound = true
        break
      }
    }
    
    expect(ctaFound).toBe(true)
  })

  test('should handle pricing toggle functionality', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Look for pricing toggle (monthly/yearly)
    const toggleSelectors = [
      '[data-testid="pricing-toggle"]',
      'button:has-text("Monthly")',
      'button:has-text("Yearly")',
      'input[type="radio"]',
      '[role="switch"]'
    ]
    
    let toggleFound = false
    for (const selector of toggleSelectors) {
      const toggles = page.locator(selector)
      if (await toggles.count() > 0) {
        const toggle = toggles.first()
        await expect(toggle).toBeVisible()
        await expect(toggle).toBeEnabled()
        toggleFound = true
        break
      }
    }
    
    // If toggle found, test interaction
    if (toggleFound) {
      const toggle = page.locator(toggleSelectors.find(s => page.locator(s).count() > 0) || toggleSelectors[0]).first()
      await toggle.click()
      // Verify state change (this would depend on implementation)
    }
  })

  test('should accept form input', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Look for email input fields
    const emailSelectors = [
      'input[type="email"]',
      'input[placeholder*="email" i]',
      '[data-testid="email-input"]',
      'input[name*="email" i]'
    ]
    
    let inputFound = false
    for (const selector of emailSelectors) {
      const inputs = page.locator(selector)
      if (await inputs.count() > 0) {
        const input = inputs.first()
        await expect(input).toBeVisible()
        await expect(input).toBeEnabled()
        
        // Test typing
        await input.fill('test@example.com')
        await expect(input).toHaveValue('test@example.com')
        inputFound = true
        break
      }
    }
    
    // If no email input, check for any text input
    if (!inputFound) {
      const textInputs = page.locator('input[type="text"]')
      if (await textInputs.count() > 0) {
        const input = textInputs.first()
        await input.fill('test input')
        await expect(input).toHaveValue('test input')
        inputFound = true
      }
    }
    
    expect(inputFound).toBe(true)
  })

  test('should handle navigation scrolling', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Look for navigation links
    const navSelectors = [
      'nav a[href*="#"]',
      'a[href="#features"]',
      'a[href="#pricing"]',
      'a[href="#testimonials"]'
    ]
    
    let navFound = false
    for (const selector of navSelectors) {
      const links = page.locator(selector)
      if (await links.count() > 0) {
        const link = links.first()
        await expect(link).toBeVisible()
        
        // Test click and scroll
        await link.click()
        await page.waitForTimeout(500) // Wait for scroll animation
        
        navFound = true
        break
      }
    }
    
    // If no navigation links, test manual scrolling
    if (!navFound) {
      await page.evaluate(() => window.scrollTo(0, 500))
      await page.waitForTimeout(500)
      const scrollY = await page.evaluate(() => window.scrollY)
      expect(scrollY).toBeGreaterThan(0)
    }
  })
})

test.describe('Landing Page - Responsive Design', () => {
  const viewports = [
    { name: 'Mobile', width: 375, height: 667 },
    { name: 'Tablet', width: 768, height: 1024 },
    { name: 'Desktop', width: 1920, height: 1080 }
  ]

  for (const viewport of viewports) {
    test(`should render correctly on ${viewport.name}`, async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height })
      await page.goto(LANDING_PAGE_URL)
      await page.waitForLoadState('networkidle')
      
      // Check that main content is visible
      await expect(page.locator('main, [role="main"]')).toBeVisible()
      
      // Check that text is readable (not too small)
      const bodyText = page.locator('body')
      const fontSize = await bodyText.evaluate(el => {
        const style = window.getComputedStyle(el)
        return parseFloat(style.fontSize)
      })
      
      expect(fontSize).toBeGreaterThan(12) // Minimum readable font size
      
      // Check for horizontal scroll (should not exist)
      const hasHorizontalScroll = await page.evaluate(() => {
        return document.documentElement.scrollWidth > document.documentElement.clientWidth
      })
      
      expect(hasHorizontalScroll).toBe(false)
    })
  }

  test('should adapt grid layouts for different screen sizes', async ({ page }) => {
    // Test mobile layout
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Check that grid items stack vertically on mobile
    const gridItems = page.locator('[class*="grid"] > *')
    if (await gridItems.count() > 0) {
      const firstItem = gridItems.first()
      const secondItem = gridItems.nth(1)
      
      if (await secondItem.count() > 0) {
        const firstRect = await firstItem.boundingBox()
        const secondRect = await secondItem.boundingBox()
        
        if (firstRect && secondRect) {
          // On mobile, items should stack (second item below first)
          expect(secondRect.y).toBeGreaterThan(firstRect.y)
        }
      }
    }
    
    // Test desktop layout
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.waitForLoadState('networkidle')
    
    // On desktop, items might be side by side
    // This test would depend on the specific grid implementation
  })
})

test.describe('Landing Page - Accessibility', () => {
  test('should have no critical accessibility violations', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    const accessibilityScanResults = await new AxeBuilder({ page }).analyze()
    
    // Filter for critical violations only
    const criticalViolations = accessibilityScanResults.violations.filter(
      violation => violation.impact === 'critical'
    )
    
    expect(criticalViolations).toHaveLength(0)
  })

  test('should have proper ARIA labels on interactive elements', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Check buttons have accessible names
    const buttons = page.locator('button')
    const buttonCount = await buttons.count()
    
    for (let i = 0; i < Math.min(buttonCount, 5); i++) {
      const button = buttons.nth(i)
      const accessibleName = await button.evaluate(el => {
        return el.getAttribute('aria-label') || 
               el.getAttribute('aria-labelledby') || 
               el.textContent?.trim() ||
               el.getAttribute('title')
      })
      
      expect(accessibleName).toBeTruthy()
    }
  })

  test('should support keyboard navigation', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Test tab navigation
    await page.keyboard.press('Tab')
    
    // Check that focus is visible
    const focusedElement = page.locator(':focus')
    await expect(focusedElement).toBeVisible()
    
    // Test that focus indicator is visible
    const focusStyles = await focusedElement.evaluate(el => {
      const style = window.getComputedStyle(el)
      return {
        outline: style.outline,
        outlineWidth: style.outlineWidth,
        boxShadow: style.boxShadow
      }
    })
    
    const hasFocusIndicator = focusStyles.outline !== 'none' || 
                             focusStyles.outlineWidth !== '0px' ||
                             focusStyles.boxShadow !== 'none'
    
    expect(hasFocusIndicator).toBe(true)
  })

  test('should have proper color contrast', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa'])
      .analyze()
    
    const colorContrastViolations = accessibilityScanResults.violations.filter(
      violation => violation.id === 'color-contrast'
    )
    
    expect(colorContrastViolations).toHaveLength(0)
  })
})

test.describe('Landing Page - Performance', () => {
  test('should load within performance budget', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    const metrics = await measurePerformance(page)
    
    // Performance assertions
    expect(metrics.loadTime).toBeLessThan(3000) // 3 seconds
    expect(metrics.domContentLoaded).toBeLessThan(2000) // 2 seconds
    expect(metrics.firstContentfulPaint).toBeLessThan(1500) // 1.5 seconds
  })

  test('should have no layout shifts', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    
    // Measure Cumulative Layout Shift
    const cls = await page.evaluate(() => {
      return new Promise((resolve) => {
        let clsValue = 0
        new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            if (!entry.hadRecentInput) {
              clsValue += (entry as any).value
            }
          }
          resolve(clsValue)
        }).observe({ entryTypes: ['layout-shift'] })
        
        // Resolve after 5 seconds if no layout shifts
        setTimeout(() => resolve(clsValue), 5000)
      })
    })
    
    expect(cls).toBeLessThan(0.1) // CLS should be less than 0.1
  })

  test('should load images efficiently', async ({ page }) => {
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Check for lazy loading on images
    const images = page.locator('img')
    const imageCount = await images.count()
    
    if (imageCount > 0) {
      const firstImage = images.first()
      const loadingAttribute = await firstImage.getAttribute('loading')
      
      // Images should have lazy loading or be optimized
      expect(['lazy', 'eager']).toContain(loadingAttribute)
    }
  })
})

test.describe('Landing Page - React Error Detection', () => {
  test('should have no React rendering errors', async ({ page }) => {
    const reactErrors: string[] = []
    
    page.on('console', msg => {
      if (msg.type() === 'error') {
        const text = msg.text()
        if (text.includes('Objects are not valid as a React child') ||
            text.includes('Cannot read properties of null') ||
            text.includes('React') ||
            text.includes('hydration')) {
          reactErrors.push(text)
        }
      }
    })
    
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Wait a bit more to catch any delayed errors
    await page.waitForTimeout(2000)
    
    expect(reactErrors).toHaveLength(0)
  })

  test('should handle component re-renders without errors', async ({ page }) => {
    const reactErrors: string[] = []
    
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().includes('React')) {
        reactErrors.push(msg.text())
      }
    })
    
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Trigger re-renders by interacting with the page
    await page.click('body') // Click to trigger any click handlers
    await page.keyboard.press('Tab') // Tab to trigger focus events
    await page.hover('button') // Hover to trigger hover effects
    
    // Wait for any async operations
    await page.waitForTimeout(1000)
    
    expect(reactErrors).toHaveLength(0)
  })

  test('should handle dynamic content without hydration mismatches', async ({ page }) => {
    const hydrationErrors: string[] = []
    
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().includes('hydration')) {
        hydrationErrors.push(msg.text())
      }
    })
    
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Refresh the page to test hydration
    await page.reload()
    await page.waitForLoadState('networkidle')
    
    expect(hydrationErrors).toHaveLength(0)
  })
})
