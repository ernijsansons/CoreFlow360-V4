import { test, expect } from '@playwright/test'

// Visual regression test configuration
const LANDING_PAGE_URL = '/landing'
const VIEWPORTS = [
  { name: 'mobile', width: 375, height: 667 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1920, height: 1080 }
]

test.describe('Landing Page - Visual Regression Tests', () => {
  // Full page screenshots for each viewport
  for (const viewport of VIEWPORTS) {
    test(`full page screenshot - ${viewport.name}`, async ({ page }) => {
      await page.setViewportSize({ width: viewport.width, height: viewport.height })
      await page.goto(LANDING_PAGE_URL)
      await page.waitForLoadState('networkidle')
      
      // Wait for animations to complete
      await page.waitForTimeout(2000)
      
      // Take full page screenshot
      await expect(page).toHaveScreenshot(`landing-page-${viewport.name}.png`, {
        fullPage: true,
        animations: 'disabled'
      })
    })
  }

  // Hero section screenshots
  test('hero section - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Try to locate hero section
    const heroSelectors = [
      '[data-testid="hero-section"]',
      'section:first-of-type',
      'main > section:first-child',
      '[class*="hero"]'
    ]
    
    let heroSection = null
    for (const selector of heroSelectors) {
      if (await page.locator(selector).count() > 0) {
        heroSection = page.locator(selector).first()
        break
      }
    }
    
    if (heroSection) {
      await expect(heroSection).toHaveScreenshot('hero-section-desktop.png')
    } else {
      // Fallback: screenshot first 800px of page
      await expect(page).toHaveScreenshot('hero-section-desktop.png', {
        clip: { x: 0, y: 0, width: 1920, height: 800 }
      })
    }
  })

  // Features section screenshots
  test('features section - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Scroll to features section
    await page.evaluate(() => {
      const featuresSection = document.querySelector('[data-testid="features-section"]') ||
                             document.querySelector('#features') ||
                             document.querySelector('section:nth-of-type(2)')
      if (featuresSection) {
        featuresSection.scrollIntoView({ behavior: 'smooth' })
      }
    })
    
    await page.waitForTimeout(1000)
    
    // Try to locate features section
    const featuresSelectors = [
      '[data-testid="features-section"]',
      '#features',
      'section:nth-of-type(2)',
      '[class*="feature"]'
    ]
    
    let featuresSection = null
    for (const selector of featuresSelectors) {
      if (await page.locator(selector).count() > 0) {
        featuresSection = page.locator(selector).first()
        break
      }
    }
    
    if (featuresSection) {
      await expect(featuresSection).toHaveScreenshot('features-section-desktop.png')
    } else {
      // Fallback: screenshot middle section of page
      await expect(page).toHaveScreenshot('features-section-desktop.png', {
        clip: { x: 0, y: 800, width: 1920, height: 800 }
      })
    }
  })

  // Pricing section screenshots
  test('pricing section - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Scroll to pricing section
    await page.evaluate(() => {
      const pricingSection = document.querySelector('[data-testid="pricing-section"]') ||
                            document.querySelector('#pricing') ||
                            document.querySelector('section:nth-of-type(3)')
      if (pricingSection) {
        pricingSection.scrollIntoView({ behavior: 'smooth' })
      }
    })
    
    await page.waitForTimeout(1000)
    
    // Try to locate pricing section
    const pricingSelectors = [
      '[data-testid="pricing-section"]',
      '#pricing',
      'section:nth-of-type(3)',
      '[class*="pricing"]'
    ]
    
    let pricingSection = null
    for (const selector of pricingSelectors) {
      if (await page.locator(selector).count() > 0) {
        pricingSection = page.locator(selector).first()
        break
      }
    }
    
    if (pricingSection) {
      await expect(pricingSection).toHaveScreenshot('pricing-section-desktop.png')
    } else {
      // Fallback: screenshot lower section of page
      await expect(page).toHaveScreenshot('pricing-section-desktop.png', {
        clip: { x: 0, y: 1600, width: 1920, height: 800 }
      })
    }
  })

  // Testimonials section screenshots
  test('testimonials section - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Scroll to testimonials section
    await page.evaluate(() => {
      const testimonialsSection = document.querySelector('[data-testid="testimonials-section"]') ||
                                 document.querySelector('#testimonials') ||
                                 document.querySelector('section:nth-of-type(4)')
      if (testimonialsSection) {
        testimonialsSection.scrollIntoView({ behavior: 'smooth' })
      }
    })
    
    await page.waitForTimeout(1000)
    
    // Try to locate testimonials section
    const testimonialsSelectors = [
      '[data-testid="testimonials-section"]',
      '#testimonials',
      'section:nth-of-type(4)',
      '[class*="testimonial"]'
    ]
    
    let testimonialsSection = null
    for (const selector of testimonialsSelectors) {
      if (await page.locator(selector).count() > 0) {
        testimonialsSection = page.locator(selector).first()
        break
      }
    }
    
    if (testimonialsSection) {
      await expect(testimonialsSection).toHaveScreenshot('testimonials-section-desktop.png')
    } else {
      // Fallback: screenshot another section of page
      await expect(page).toHaveScreenshot('testimonials-section-desktop.png', {
        clip: { x: 0, y: 2400, width: 1920, height: 800 }
      })
    }
  })

  // Footer section screenshots
  test('footer section - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Scroll to bottom of page
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight))
    await page.waitForTimeout(1000)
    
    // Try to locate footer section
    const footerSelectors = [
      '[data-testid="footer-section"]',
      'footer',
      '[class*="footer"]',
      'section:last-of-type'
    ]
    
    let footerSection = null
    for (const selector of footerSelectors) {
      if (await page.locator(selector).count() > 0) {
        footerSection = page.locator(selector).first()
        break
      }
    }
    
    if (footerSection) {
      await expect(footerSection).toHaveScreenshot('footer-section-desktop.png')
    } else {
      // Fallback: screenshot bottom of page
      await expect(page).toHaveScreenshot('footer-section-desktop.png', {
        clip: { x: 0, y: -800, width: 1920, height: 800 }
      })
    }
  })

  // Dark theme screenshots (if theme toggle exists)
  test('dark theme - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Try to find and click theme toggle
    const themeToggleSelectors = [
      '[data-testid="theme-toggle"]',
      'button[aria-label*="theme" i]',
      'button[aria-label*="dark" i]',
      'button[aria-label*="light" i]',
      '[class*="theme-toggle"]',
      'button:has-text("Dark")',
      'button:has-text("Light")'
    ]
    
    let themeToggled = false
    for (const selector of themeToggleSelectors) {
      const toggle = page.locator(selector)
      if (await toggle.count() > 0) {
        await toggle.click()
        await page.waitForTimeout(500) // Wait for theme change
        themeToggled = true
        break
      }
    }
    
    if (themeToggled) {
      // Take screenshot of dark theme
      await expect(page).toHaveScreenshot('landing-page-dark-theme-desktop.png', {
        fullPage: true,
        animations: 'disabled'
      })
    } else {
      // Skip test if no theme toggle found
      test.skip(true, 'No theme toggle found')
    }
  })

  // Mobile-specific visual tests
  test('mobile navigation - mobile viewport', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Look for mobile menu button
    const mobileMenuSelectors = [
      '[data-testid="mobile-menu-button"]',
      'button[aria-label*="menu" i]',
      'button[aria-label*="navigation" i]',
      '[class*="hamburger"]',
      '[class*="mobile-menu"]'
    ]
    
    let mobileMenuButton = null
    for (const selector of mobileMenuSelectors) {
      if (await page.locator(selector).count() > 0) {
        mobileMenuButton = page.locator(selector).first()
        break
      }
    }
    
    if (mobileMenuButton) {
      // Screenshot before opening menu
      await expect(page).toHaveScreenshot('mobile-navigation-closed.png', {
        clip: { x: 0, y: 0, width: 375, height: 200 }
      })
      
      // Click to open mobile menu
      await mobileMenuButton.click()
      await page.waitForTimeout(500)
      
      // Screenshot with menu open
      await expect(page).toHaveScreenshot('mobile-navigation-open.png', {
        clip: { x: 0, y: 0, width: 375, height: 400 }
      })
    } else {
      // Fallback: screenshot header area
      await expect(page).toHaveScreenshot('mobile-header.png', {
        clip: { x: 0, y: 0, width: 375, height: 200 }
      })
    }
  })

  // Pricing toggle visual test
  test('pricing toggle states - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Scroll to pricing section
    await page.evaluate(() => {
      const pricingSection = document.querySelector('[data-testid="pricing-section"]') ||
                            document.querySelector('#pricing')
      if (pricingSection) {
        pricingSection.scrollIntoView({ behavior: 'smooth' })
      }
    })
    
    await page.waitForTimeout(1000)
    
    // Look for pricing toggle
    const pricingToggleSelectors = [
      '[data-testid="pricing-toggle"]',
      'button:has-text("Monthly")',
      'button:has-text("Yearly")',
      'input[type="radio"]',
      '[role="switch"]'
    ]
    
    let pricingToggle = null
    for (const selector of pricingToggleSelectors) {
      if (await page.locator(selector).count() > 0) {
        pricingToggle = page.locator(selector).first()
        break
      }
    }
    
    if (pricingToggle) {
      // Screenshot pricing section with default state
      await expect(page).toHaveScreenshot('pricing-toggle-monthly.png', {
        clip: { x: 0, y: 0, width: 1920, height: 800 }
      })
      
      // Click toggle to change state
      await pricingToggle.click()
      await page.waitForTimeout(500)
      
      // Screenshot pricing section with toggled state
      await expect(page).toHaveScreenshot('pricing-toggle-yearly.png', {
        clip: { x: 0, y: 0, width: 1920, height: 800 }
      })
    } else {
      // Fallback: screenshot pricing section as-is
      await expect(page).toHaveScreenshot('pricing-section-no-toggle.png', {
        clip: { x: 0, y: 0, width: 1920, height: 800 }
      })
    }
  })

  // Form interaction visual test
  test('form interaction states - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Look for email input
    const emailInputSelectors = [
      'input[type="email"]',
      'input[placeholder*="email" i]',
      '[data-testid="email-input"]',
      'input[name*="email" i]'
    ]
    
    let emailInput = null
    for (const selector of emailInputSelectors) {
      if (await page.locator(selector).count() > 0) {
        emailInput = page.locator(selector).first()
        break
      }
    }
    
    if (emailInput) {
      // Screenshot form in default state
      await expect(emailInput).toHaveScreenshot('form-input-default.png')
      
      // Focus the input
      await emailInput.focus()
      await page.waitForTimeout(200)
      
      // Screenshot form with focus state
      await expect(emailInput).toHaveScreenshot('form-input-focused.png')
      
      // Type in the input
      await emailInput.fill('test@example.com')
      await page.waitForTimeout(200)
      
      // Screenshot form with filled state
      await expect(emailInput).toHaveScreenshot('form-input-filled.png')
    } else {
      // Skip if no email input found
      test.skip(true, 'No email input found')
    }
  })

  // Error state visual test (if applicable)
  test('error states - desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 })
    await page.goto(LANDING_PAGE_URL)
    await page.waitForLoadState('networkidle')
    
    // Look for form with validation
    const formSelectors = [
      'form',
      '[data-testid="signup-form"]',
      '[data-testid="contact-form"]'
    ]
    
    let form = null
    for (const selector of formSelectors) {
      if (await page.locator(selector).count() > 0) {
        form = page.locator(selector).first()
        break
      }
    }
    
    if (form) {
      // Try to trigger validation error
      const submitButton = form.locator('button[type="submit"], input[type="submit"]')
      if (await submitButton.count() > 0) {
        await submitButton.click()
        await page.waitForTimeout(500)
        
        // Screenshot form with validation errors
        await expect(form).toHaveScreenshot('form-validation-errors.png')
      }
    } else {
      // Skip if no form found
      test.skip(true, 'No form found for error state testing')
    }
  })
})

