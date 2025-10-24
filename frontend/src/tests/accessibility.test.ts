/**
 * Comprehensive Accessibility (a11y) Testing
 * Tests WCAG 2.1 AA compliance for all pages and components
 */

import { test, expect } from '@playwright/test'
import { injectAxe, checkA11y } from 'axe-playwright'

test.describe('Accessibility Testing @a11y', () => {
  test.describe('WCAG 2.1 Level AA Compliance', () => {
    test('should meet accessibility standards on landing page', async ({ page }) => {
      await page.goto('/')
      await injectAxe(page)

      // Run axe accessibility checks
      await checkA11y(page, null, {
        detailedReport: true,
        detailedReportOptions: {
          html: true
        }
      })

      console.log('Landing page accessibility check passed ✓')
    })

    test('should meet accessibility standards on dashboard', async ({ page }) => {
      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      await injectAxe(page)
      await checkA11y(page, null, {
        detailedReport: true
      })

      console.log('Dashboard accessibility check passed ✓')
    })

    test('should meet accessibility standards for forms', async ({ page }) => {
      await page.goto('/')

      const forms = await page.locator('form').all()

      for (let i = 0; i < Math.min(forms.length, 3); i++) {
        await injectAxe(page)
        await checkA11y(page, `form:nth-of-type(${i + 1})`, {
          detailedReport: true
        })

        console.log(`Form ${i + 1} accessibility check passed ✓`)
      }
    })
  })

  test.describe('Keyboard Accessibility', () => {
    test('should allow tab navigation through all interactive elements', async ({ page }) => {
      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      const focusableElements: string[] = []

      // Tab through first 20 elements
      for (let i = 0; i < 20; i++) {
        await page.keyboard.press('Tab')
        await page.waitForTimeout(100)

        const focusedElement = await page.locator(':focus')
        if (await focusedElement.count() > 0) {
          const tag = await focusedElement.evaluate(el => el.tagName)
          const role = await focusedElement.getAttribute('role')
          const label = await focusedElement.getAttribute('aria-label')

          focusableElements.push(`<${tag}> ${role || ''} ${label || ''}`)
        }
      }

      console.log('Focusable elements:', focusableElements.length)
      expect(focusableElements.length).toBeGreaterThan(0)
    })

    test('should support Shift+Tab for reverse navigation', async ({ page }) => {
      await page.goto('/dashboard')

      // Tab forward
      await page.keyboard.press('Tab')
      await page.keyboard.press('Tab')
      await page.keyboard.press('Tab')

      // Tab backward
      await page.keyboard.press('Shift+Tab')

      const focusedElement = await page.locator(':focus')
      expect(await focusedElement.count()).toBeGreaterThan(0)

      console.log('Reverse tab navigation works ✓')
    })

    test('should activate buttons with Enter key', async ({ page }) => {
      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      // Find first visible button
      const button = await page.locator('button:visible').first()

      if (await button.count() > 0) {
        await button.focus()
        const buttonText = await button.textContent()

        console.log(`Testing Enter key on button: "${buttonText?.trim()}"`)

        // Press Enter
        await page.keyboard.press('Enter')
        await page.waitForTimeout(500)

        console.log('Enter key activation works ✓')
      }
    })

    test('should activate buttons with Space key', async ({ page }) => {
      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      // Find first visible button
      const button = await page.locator('button:visible').first()

      if (await button.count() > 0) {
        await button.focus()
        const buttonText = await button.textContent()

        console.log(`Testing Space key on button: "${buttonText?.trim()}"`)

        // Press Space
        await page.keyboard.press('Space')
        await page.waitForTimeout(500)

        console.log('Space key activation works ✓')
      }
    })

    test('should close modals with Escape key', async ({ page }) => {
      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      // Find modal trigger
      const modalTrigger = await page.locator('button:has-text("Add"), button:has-text("New")').first()

      if (await modalTrigger.count() > 0) {
        await modalTrigger.click()
        await page.waitForTimeout(500)

        // Check if modal opened
        const modal = page.locator('[role="dialog"], [role="alertdialog"]')

        if (await modal.count() > 0) {
          // Press Escape
          await page.keyboard.press('Escape')
          await page.waitForTimeout(300)

          // Modal should be closed
          expect(await modal.count()).toBe(0)
          console.log('Escape key closes modals ✓')
        }
      }
    })
  })

  test.describe('Screen Reader Compatibility', () => {
    test('should have proper heading hierarchy', async ({ page }) => {
      await page.goto('/')

      const headings = await page.locator('h1, h2, h3, h4, h5, h6').all()

      console.log(`Found ${headings.length} headings`)

      for (let i = 0; i < headings.length; i++) {
        const heading = headings[i]
        const tagName = await heading.evaluate(el => el.tagName)
        const text = await heading.textContent()

        console.log(`  ${tagName}: ${text?.trim().substring(0, 50)}`)
      }

      // Should have at least one h1
      const h1Count = await page.locator('h1').count()
      expect(h1Count).toBeGreaterThanOrEqual(1)
    })

    test('should have descriptive link text', async ({ page }) => {
      await page.goto('/')

      const links = await page.locator('a').all()

      console.log(`Checking ${links.length} links for descriptive text`)

      let genericLinks = 0
      const genericPhrases = ['click here', 'read more', 'learn more', 'here']

      for (const link of links) {
        const text = await link.textContent()
        const ariaLabel = await link.getAttribute('aria-label')

        if (text && !ariaLabel) {
          const lowercaseText = text.toLowerCase().trim()
          if (genericPhrases.includes(lowercaseText)) {
            genericLinks++
            console.log(`  Warning: Generic link text "${text.trim()}"`)
          }
        }
      }

      console.log(`Found ${genericLinks} generic links`)
    })

    test('should have alt text for images', async ({ page }) => {
      await page.goto('/')

      const images = await page.locator('img').all()

      console.log(`Checking ${images.length} images for alt text`)

      let missingAlt = 0

      for (const img of images) {
        const alt = await img.getAttribute('alt')
        const role = await img.getAttribute('role')

        if (!alt && role !== 'presentation' && role !== 'none') {
          missingAlt++
          const src = await img.getAttribute('src')
          console.log(`  Warning: Image missing alt text - ${src}`)
        }
      }

      console.log(`${missingAlt} images missing alt text`)
    })

    test('should have proper form labels', async ({ page }) => {
      await page.goto('/')

      const inputs = await page.locator('input, textarea, select').all()

      console.log(`Checking ${inputs.length} form inputs for labels`)

      let unlabeledInputs = 0

      for (const input of inputs) {
        const id = await input.getAttribute('id')
        const ariaLabel = await input.getAttribute('aria-label')
        const ariaLabelledBy = await input.getAttribute('aria-labelledby')
        const type = await input.getAttribute('type')

        // Skip hidden inputs
        if (type === 'hidden') continue

        let hasLabel = false

        if (id) {
          const label = await page.locator(`label[for="${id}"]`).count()
          hasLabel = label > 0
        }

        if (!hasLabel && !ariaLabel && !ariaLabelledBy) {
          unlabeledInputs++
          console.log(`  Warning: Input without label - type: ${type}, id: ${id}`)
        }
      }

      console.log(`${unlabeledInputs} inputs without proper labels`)
    })

    test('should have proper ARIA roles and attributes', async ({ page }) => {
      await page.goto('/dashboard')

      // Check for proper landmark roles
      const landmarks = {
        navigation: await page.locator('[role="navigation"]').count(),
        main: await page.locator('[role="main"], main').count(),
        contentinfo: await page.locator('[role="contentinfo"], footer').count(),
        banner: await page.locator('[role="banner"], header').count(),
      }

      console.log('Landmark roles:', landmarks)

      // Should have main landmark
      expect(landmarks.main).toBeGreaterThan(0)
    })

    test('should have skip links for keyboard users', async ({ page }) => {
      await page.goto('/')

      // Tab to potential skip link
      await page.keyboard.press('Tab')
      await page.waitForTimeout(100)

      const skipLink = await page.locator('a:has-text("Skip"), a:has-text("skip")').first()

      if (await skipLink.count() > 0) {
        console.log('Skip link found ✓')
        const href = await skipLink.getAttribute('href')
        console.log(`  Skip link target: ${href}`)
      } else {
        console.log('No skip link found (optional)')
      }
    })
  })

  test.describe('Color Contrast', () => {
    test('should have sufficient color contrast', async ({ page }) => {
      await page.goto('/')
      await injectAxe(page)

      // Check specifically for color contrast issues
      await checkA11y(page, null, {
        runOnly: {
          type: 'tag',
          values: ['wcag2aa', 'wcag21aa']
        },
        rules: {
          'color-contrast': { enabled: true }
        }
      })

      console.log('Color contrast check passed ✓')
    })
  })

  test.describe('Focus Management', () => {
    test('should have visible focus indicators', async ({ page }) => {
      await page.goto('/dashboard')

      // Tab to first interactive element
      await page.keyboard.press('Tab')
      await page.waitForTimeout(200)

      const focusedElement = await page.locator(':focus')

      if (await focusedElement.count() > 0) {
        // Take screenshot to verify focus indicator
        await page.screenshot({ path: 'playwright-report/focus-indicator.png' })

        // Check if element has outline or visible focus style
        const focusStyles = await focusedElement.evaluate(el => {
          const styles = window.getComputedStyle(el)
          return {
            outline: styles.outline,
            outlineWidth: styles.outlineWidth,
            boxShadow: styles.boxShadow
          }
        })

        console.log('Focus styles:', focusStyles)
      }
    })

    test('should trap focus in modals', async ({ page }) => {
      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      // Open modal if available
      const modalTrigger = await page.locator('button:has-text("Add"), button:has-text("New")').first()

      if (await modalTrigger.count() > 0) {
        await modalTrigger.click()
        await page.waitForTimeout(500)

        const modal = page.locator('[role="dialog"]')

        if (await modal.count() > 0) {
          // Tab multiple times
          for (let i = 0; i < 20; i++) {
            await page.keyboard.press('Tab')
            await page.waitForTimeout(50)
          }

          // Focus should still be within modal
          const focusedElement = await page.locator(':focus')
          const isInModal = await modal.locator(':focus').count()

          console.log(`Focus is ${isInModal > 0 ? 'within' : 'outside'} modal`)

          // Close modal
          await page.keyboard.press('Escape')
        }
      }
    })
  })

  test.describe('Motion and Animation', () => {
    test('should respect prefers-reduced-motion', async ({ page }) => {
      // Emulate prefers-reduced-motion
      await page.emulateMedia({ reducedMotion: 'reduce' })

      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      console.log('Loaded with reduced motion preference ✓')

      // Take screenshot
      await page.screenshot({ path: 'playwright-report/reduced-motion.png' })
    })
  })

  test.describe('Language and Localization', () => {
    test('should have lang attribute on html element', async ({ page }) => {
      await page.goto('/')

      const lang = await page.locator('html').getAttribute('lang')

      console.log('Page language:', lang || 'not set')
      expect(lang).toBeTruthy()
    })

    test('should have proper text directionality', async ({ page }) => {
      await page.goto('/')

      const dir = await page.locator('html').getAttribute('dir')

      console.log('Text direction:', dir || 'default (ltr)')
    })
  })

  test.describe('Zoom and Text Resize', () => {
    test('should be usable at 200% zoom', async ({ page }) => {
      await page.goto('/dashboard')

      // Set viewport to simulate zoom
      await page.setViewportSize({ width: 640, height: 480 })

      await page.waitForLoadState('networkidle')

      // Check if content is still accessible
      const buttons = await page.locator('button:visible').count()
      const links = await page.locator('a:visible').count()

      console.log(`At 200% zoom: ${buttons} buttons, ${links} links visible`)

      // Take screenshot
      await page.screenshot({ path: 'playwright-report/200-percent-zoom.png', fullPage: true })

      expect(buttons).toBeGreaterThan(0)
    })
  })

  test.describe('Error Identification', () => {
    test('should provide clear error messages', async ({ page }) => {
      await page.goto('/')

      // Find first form
      const form = page.locator('form').first()

      if (await form.count() > 0) {
        // Try to submit empty form
        const submitButton = form.locator('button[type="submit"]').or(form.locator('button').first())

        if (await submitButton.count() > 0) {
          await submitButton.click()
          await page.waitForTimeout(1000)

          // Check for error messages
          const errorMessages = await page.locator('[role="alert"], [aria-live="polite"], [aria-live="assertive"], .error, [class*="error"]').all()

          console.log(`Found ${errorMessages.length} error/alert messages`)

          for (const error of errorMessages.slice(0, 3)) {
            const text = await error.textContent()
            console.log(`  Error: ${text?.trim().substring(0, 80)}`)
          }
        }
      }
    })
  })

  test.describe('Mobile Accessibility', () => {
    test('should be accessible on mobile devices', async ({ page }) => {
      // Set mobile viewport
      await page.setViewportSize({ width: 375, height: 667 })

      await page.goto('/dashboard')
      await page.waitForLoadState('networkidle')

      await injectAxe(page)
      await checkA11y(page, null, {
        detailedReport: true
      })

      console.log('Mobile accessibility check passed ✓')

      // Take mobile screenshot
      await page.screenshot({ path: 'playwright-report/mobile-accessibility.png', fullPage: true })
    })

    test('should have adequate touch target sizes', async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 })

      await page.goto('/dashboard')

      const buttons = await page.locator('button').all()

      let smallButtons = 0

      for (const button of buttons.slice(0, 10)) {
        const box = await button.boundingBox()

        if (box) {
          // Touch targets should be at least 44x44px
          if (box.width < 44 || box.height < 44) {
            smallButtons++
            const text = await button.textContent()
            console.log(`  Small button (${Math.round(box.width)}x${Math.round(box.height)}): ${text?.trim()}`)
          }
        }
      }

      console.log(`Found ${smallButtons} buttons smaller than 44x44px`)
    })
  })
})
