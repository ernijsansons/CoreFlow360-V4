# Accessibility Testing Guide - WCAG 2.1 AA Compliance

**Created**: 2025-10-22
**Purpose**: Ensure all features meet WCAG 2.1 AA accessibility standards
**Target**: Lighthouse Accessibility Score ≥ 95
**Audience**: QA engineers, developers, designers

---

## Overview

**Why Accessibility Matters**:
- 📊 **15% of users** have some form of disability
- ⚖️ **Legal requirement** (ADA, Section 508)
- 💰 **Business impact** (larger addressable market)
- 🎯 **Better UX** for everyone (not just disabled users)

**Our Standard**: WCAG 2.1 AA compliance minimum

---

## Table of Contents

1. [Quick Checklist](#quick-checklist)
2. [Automated Testing](#automated-testing)
3. [Manual Testing](#manual-testing)
4. [Screen Reader Testing](#screen-reader-testing)
5. [Keyboard Navigation Testing](#keyboard-navigation-testing)
6. [Visual Accessibility Testing](#visual-accessibility-testing)
7. [Common Issues & Fixes](#common-issues--fixes)
8. [Component-Specific Guidelines](#component-specific-guidelines)

---

## Quick Checklist

### Before Every PR Merge

- [ ] **Lighthouse accessibility score ≥ 95**
- [ ] **All interactive elements keyboard accessible**
- [ ] **Color contrast ratio ≥ 4.5:1 for text**
- [ ] **Form inputs have associated labels**
- [ ] **Images have alt text**
- [ ] **Semantic HTML used (not div soup)**
- [ ] **ARIA labels on custom components**
- [ ] **Focus indicators visible**
- [ ] **No keyboard traps**
- [ ] **Tested with screen reader (5-minute smoke test)**

---

## Automated Testing

### Tool 1: Lighthouse (Built into Chrome)

```bash
# Run Lighthouse from CLI
npx lighthouse http://localhost:5173/admin/compliance/guidelines \
  --only-categories=accessibility \
  --output=html \
  --output-path=./lighthouse-report.html

# Open report
open ./lighthouse-report.html
```

**How to Run in Chrome DevTools**:
1. Open Chrome DevTools (F12)
2. Go to "Lighthouse" tab
3. Select "Accessibility" only
4. Click "Analyze page load"
5. Review score and issues

**Target**: Score ≥ 95 (100 is perfect, but 95+ is excellent)

---

### Tool 2: axe DevTools (Browser Extension)

**Installation**:
1. Install "axe DevTools" Chrome extension
2. Open any page
3. Click axe extension icon
4. Click "Scan ALL of my page"

**Benefits**:
- Detects more issues than Lighthouse
- Provides specific fix suggestions
- Highlights problematic elements on page
- Categorizes by severity (Critical, Serious, Moderate, Minor)

**Target**: Zero critical and serious issues

---

### Tool 3: eslint-plugin-jsx-a11y (Automated in CI)

```bash
# Already configured in project
# Runs automatically on npm run lint

npm run lint
```

**Catches**:
- Missing alt text on images
- Missing labels on form inputs
- Invalid ARIA attributes
- Click handlers on non-interactive elements
- Missing keyboard handlers

---

### Tool 4: Pa11y (CI Integration)

```bash
# Install
npm install -g pa11y

# Test single page
pa11y http://localhost:5173/admin/compliance/guidelines

# Test multiple pages
pa11y-ci --config pa11y-ci.json
```

**pa11y-ci.json**:
```json
{
  "defaults": {
    "standard": "WCAG2AA",
    "timeout": 10000
  },
  "urls": [
    "http://localhost:5173/admin/compliance/guidelines",
    "http://localhost:5173/admin/compliance/policies",
    "http://localhost:5173/finance/approvals"
  ]
}
```

---

## Manual Testing

### Keyboard Navigation Testing (15 minutes)

**Goal**: Navigate entire page using only keyboard

**Steps**:
1. **Load page**
2. **Press Tab repeatedly**
   - Does focus move to all interactive elements?
   - Is focus order logical (top to bottom, left to right)?
   - Are focus indicators visible?
3. **Press Shift+Tab**
   - Does backwards navigation work?
4. **Press Enter/Space on buttons**
   - Do buttons activate?
5. **Press Escape on modals**
   - Do modals close?
6. **Use arrow keys in dropdowns**
   - Can you navigate dropdown options?
7. **Use arrow keys in tables**
   - Does cell navigation work?

**Common Shortcuts**:
| Key | Action |
|-----|--------|
| Tab | Move to next focusable element |
| Shift+Tab | Move to previous element |
| Enter | Activate button/link |
| Space | Activate button, toggle checkbox |
| Escape | Close modal/menu |
| Arrow keys | Navigate list/dropdown/menu |
| Home/End | Jump to first/last item |

**Checklist**:
- [ ] All interactive elements reachable
- [ ] Focus order makes sense
- [ ] Focus indicators visible (not display:none!)
- [ ] No keyboard traps (can navigate away from every element)
- [ ] Shortcuts work as expected

---

### Screen Reader Testing (30 minutes)

**Tools**:
- **Windows**: NVDA (free) or JAWS (paid)
- **macOS**: VoiceOver (built-in, Cmd+F5 to enable)
- **Linux**: Orca (free)

#### VoiceOver Quick Start (macOS)

**Enable**:
```
Cmd + F5 (or System Preferences → Accessibility → VoiceOver)
```

**Basic Commands**:
| Command | Action |
|---------|--------|
| VO + A | Start reading from cursor |
| VO + Right Arrow | Next item |
| VO + Left Arrow | Previous item |
| VO + Space | Activate item |
| VO + H | Next heading |
| VO + Shift + H | Previous heading |
| VO + U | Open rotor (elements list) |

**VO = Control + Option**

**Test Scenarios**:

**Scenario 1: Form Submission** (5 min)
1. Navigate to Compliance Guidelines page
2. Use VoiceOver to find "Create Guideline" button
3. Activate button
4. Fill form using VoiceOver
5. Verify:
   - [ ] Field labels are read aloud
   - [ ] Required fields announced
   - [ ] Error messages read automatically
   - [ ] Success message read after submission

**Scenario 2: Table Navigation** (5 min)
1. Navigate to Guidelines table
2. Use VoiceOver to navigate table
3. Verify:
   - [ ] Table structure announced ("Table with 20 rows, 5 columns")
   - [ ] Column headers read
   - [ ] Cell content read
   - [ ] Row actions announced

**Scenario 3: Modal Interaction** (5 min)
1. Open guideline edit modal
2. Verify:
   - [ ] Focus moves to modal automatically
   - [ ] Modal title announced
   - [ ] Can navigate modal content
   - [ ] Escape closes modal
   - [ ] Focus returns to trigger after close

---

## Visual Accessibility Testing

### Color Contrast Testing

**Tool**: WebAIM Contrast Checker (https://webaim.org/resources/contrastchecker/)

**Standards**:
- **Normal text (< 24px)**: 4.5:1 contrast ratio minimum
- **Large text (≥ 24px)**: 3.0:1 contrast ratio minimum
- **UI components**: 3.0:1 contrast ratio minimum

**How to Test**:
1. Take screenshot of page
2. Use eyedropper tool to get foreground and background colors
3. Enter colors into contrast checker
4. Verify meets WCAG AA standards

**Common Issues**:
- ❌ Gray text on white background (#999 on #FFF = 2.85:1) - FAIL
- ✅ Dark gray on white (#555 on #FFF = 7.42:1) - PASS
- ❌ Light blue on white (#6AB7FF on #FFF = 2.33:1) - FAIL
- ✅ Blue on white (#0066CC on #FFF = 7.21:1) - PASS

---

### Focus Indicator Testing

**Requirement**: Focus indicators must be visible with ≥ 3:1 contrast

**Test**:
1. Navigate page with Tab key
2. Verify every focusable element shows focus indicator
3. Measure contrast of focus indicator against background

**Default Browser Styles**:
```css
/* ❌ BAD: Removing focus outline */
button:focus {
  outline: none; /* Never do this! */
}

/* ✅ GOOD: Custom focus indicator */
button:focus-visible {
  outline: 2px solid #0066CC;
  outline-offset: 2px;
}

/* ✅ BETTER: Accessible focus ring */
button:focus-visible {
  outline: 3px solid #0066CC;
  outline-offset: 2px;
  box-shadow: 0 0 0 3px rgba(0, 102, 204, 0.3);
}
```

---

### Text Scaling Testing

**Requirement**: Page must be usable at 200% text zoom

**Test**:
1. Open page in browser
2. Zoom to 200% (Cmd/Ctrl + +)
3. Verify:
   - [ ] All text visible (no cutoff)
   - [ ] No horizontal scrolling
   - [ ] Layout doesn't break
   - [ ] Interactive elements still clickable

**Common Issues**:
- Fixed pixel widths cause text overflow
- Absolute positioning breaks layout
- Line-height too small causes text overlap

---

## Common Issues & Fixes

### Issue 1: Missing Form Labels

**Problem**:
```tsx
// ❌ BAD: No associated label
<input type="text" placeholder="Title" />
```

**Fix**:
```tsx
// ✅ GOOD: Explicit label
<label htmlFor="title">Title</label>
<input type="text" id="title" />

// ✅ ALSO GOOD: Implicit label
<label>
  Title
  <input type="text" />
</label>

// ✅ ALSO GOOD: aria-label (if visual label not possible)
<input type="text" aria-label="Title" />
```

---

### Issue 2: Missing Button Text

**Problem**:
```tsx
// ❌ BAD: Icon button with no text
<button onClick={handleDelete}>
  <TrashIcon />
</button>
```

**Fix**:
```tsx
// ✅ GOOD: aria-label
<button onClick={handleDelete} aria-label="Delete guideline">
  <TrashIcon />
</button>

// ✅ BETTER: Visible label + icon
<button onClick={handleDelete}>
  <TrashIcon />
  <span>Delete</span>
</button>

// ✅ ALSO GOOD: Visually hidden label
<button onClick={handleDelete}>
  <TrashIcon />
  <span className="sr-only">Delete guideline</span>
</button>
```

```css
/* Screen reader only class */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}
```

---

### Issue 3: Missing Alt Text

**Problem**:
```tsx
// ❌ BAD: No alt text
<img src="/logo.png" />
```

**Fix**:
```tsx
// ✅ GOOD: Descriptive alt text
<img src="/logo.png" alt="CoreFlow360 logo" />

// ✅ GOOD: Empty alt for decorative images
<img src="/decoration.png" alt="" />

// ❌ BAD: Redundant alt text
<img src="/logo.png" alt="Image of logo" /> // Don't say "image of"
```

---

### Issue 4: Non-Semantic HTML

**Problem**:
```tsx
// ❌ BAD: Div soup
<div onClick={handleClick}>Click me</div>
```

**Fix**:
```tsx
// ✅ GOOD: Semantic HTML
<button onClick={handleClick}>Click me</button>

// ✅ GOOD: Role attribute if div necessary
<div role="button" tabIndex={0} onClick={handleClick} onKeyPress={handleKeyPress}>
  Click me
</div>
```

---

### Issue 5: Missing ARIA Labels on Custom Components

**Problem**:
```tsx
// ❌ BAD: Custom dropdown with no labels
<div className="dropdown">
  <div className="trigger">Select option</div>
  <div className="menu">...</div>
</div>
```

**Fix**:
```tsx
// ✅ GOOD: ARIA attributes
<div className="dropdown">
  <button
    aria-haspopup="true"
    aria-expanded={isOpen}
    aria-controls="dropdown-menu"
  >
    Select option
  </button>
  <div
    id="dropdown-menu"
    role="menu"
    aria-labelledby="dropdown-trigger"
  >
    <button role="menuitem">Option 1</button>
    <button role="menuitem">Option 2</button>
  </div>
</div>
```

---

## Component-Specific Guidelines

### DataTable

**Requirements**:
- [ ] Use `<table>`, `<thead>`, `<tbody>`, `<th>`, `<td>` semantic elements
- [ ] Column headers have `scope="col"`
- [ ] Row headers (if any) have `scope="row"`
- [ ] Caption or aria-label on table
- [ ] Sortable columns announce sort state
- [ ] Pagination keyboard accessible

**Example**:
```tsx
<table aria-label="Compliance guidelines">
  <caption className="sr-only">
    List of compliance guidelines with 20 items
  </caption>
  <thead>
    <tr>
      <th scope="col">Title</th>
      <th scope="col">Category</th>
      <th scope="col">Severity</th>
      <th scope="col">Actions</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>GDPR Compliance</td>
      <td>REGULATION</td>
      <td>
        <span aria-label="High severity">HIGH</span>
      </td>
      <td>
        <button aria-label="Edit GDPR Compliance guideline">Edit</button>
      </td>
    </tr>
  </tbody>
</table>
```

---

### Modal/Dialog

**Requirements**:
- [ ] `role="dialog"` on modal container
- [ ] `aria-modal="true"`
- [ ] `aria-labelledby` pointing to title
- [ ] Focus trapped inside modal
- [ ] Escape key closes modal
- [ ] Focus returns to trigger on close

**Example**:
```tsx
<div
  role="dialog"
  aria-modal="true"
  aria-labelledby="modal-title"
>
  <h2 id="modal-title">Edit Guideline</h2>
  <form>...</form>
  <button onClick={handleClose}>Cancel</button>
  <button type="submit">Save</button>
</div>
```

**Focus Trap Hook**:
```tsx
export function useFocusTrap(ref: RefObject<HTMLElement>, isActive: boolean) {
  useEffect(() => {
    if (!isActive || !ref.current) return

    const focusableElements = ref.current.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )

    const firstElement = focusableElements[0] as HTMLElement
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement

    const handleTab = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return

      if (e.shiftKey) {
        if (document.activeElement === firstElement) {
          e.preventDefault()
          lastElement?.focus()
        }
      } else {
        if (document.activeElement === lastElement) {
          e.preventDefault()
          firstElement?.focus()
        }
      }
    }

    document.addEventListener('keydown', handleTab)
    firstElement?.focus()

    return () => {
      document.removeEventListener('keydown', handleTab)
    }
  }, [isActive, ref])
}
```

---

### Form

**Requirements**:
- [ ] All inputs have labels
- [ ] Required fields marked with `aria-required="true"`
- [ ] Error messages associated with fields (`aria-describedby`)
- [ ] Validation errors announced to screen readers
- [ ] Submit button has clear text

**Example**:
```tsx
<form onSubmit={handleSubmit}>
  <div>
    <label htmlFor="title">
      Title <span aria-label="required">*</span>
    </label>
    <input
      type="text"
      id="title"
      aria-required="true"
      aria-invalid={!!errors.title}
      aria-describedby={errors.title ? "title-error" : undefined}
    />
    {errors.title && (
      <span id="title-error" role="alert">
        {errors.title.message}
      </span>
    )}
  </div>

  <button type="submit">Create Guideline</button>
</form>
```

---

### Dropdown/Select

**Requirements**:
- [ ] Button has `aria-haspopup="true"`
- [ ] Button has `aria-expanded` (true/false)
- [ ] Menu has `role="menu"`
- [ ] Menu items have `role="menuitem"`
- [ ] Arrow keys navigate items
- [ ] Enter/Space selects item
- [ ] Escape closes menu

**Example**:
```tsx
export function Dropdown({ options, value, onChange }: Props) {
  const [isOpen, setIsOpen] = useState(false)
  const [focusedIndex, setFocusedIndex] = useState(0)

  const handleKeyDown = (e: KeyboardEvent) => {
    if (!isOpen) return

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setFocusedIndex((i) => Math.min(i + 1, options.length - 1))
        break
      case 'ArrowUp':
        e.preventDefault()
        setFocusedIndex((i) => Math.max(i - 1, 0))
        break
      case 'Enter':
      case ' ':
        e.preventDefault()
        onChange(options[focusedIndex])
        setIsOpen(false)
        break
      case 'Escape':
        setIsOpen(false)
        break
    }
  }

  return (
    <div>
      <button
        onClick={() => setIsOpen(!isOpen)}
        aria-haspopup="true"
        aria-expanded={isOpen}
      >
        {value || 'Select option'}
      </button>

      {isOpen && (
        <div role="menu" onKeyDown={handleKeyDown}>
          {options.map((option, index) => (
            <button
              key={option}
              role="menuitem"
              tabIndex={index === focusedIndex ? 0 : -1}
              onClick={() => {
                onChange(option)
                setIsOpen(false)
              }}
            >
              {option}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
```

---

## Automated Testing in CI

### Playwright Accessibility Tests

```typescript
// e2e/compliance/guidelines.spec.ts
import { test, expect } from '@playwright/test'
import { injectAxe, checkA11y } from 'axe-playwright'

test.describe('Compliance Guidelines - Accessibility', () => {
  test('should have no accessibility violations', async ({ page }) => {
    await page.goto('/admin/compliance/guidelines')

    // Inject axe
    await injectAxe(page)

    // Check entire page
    await checkA11y(page, null, {
      detailedReport: true,
      detailedReportOptions: { html: true },
    })
  })

  test('should be keyboard navigable', async ({ page }) => {
    await page.goto('/admin/compliance/guidelines')

    // Tab through all focusable elements
    const focusableElements = await page.locator('a, button, input, select, textarea, [tabindex]:not([tabindex="-1"])').count()

    for (let i = 0; i < focusableElements; i++) {
      await page.keyboard.press('Tab')
      const focused = await page.locator(':focus')
      // Verify focus indicator visible
      const outline = await focused.evaluate((el) =>
        window.getComputedStyle(el).outline
      )
      expect(outline).not.toBe('none')
    }
  })

  test('form should be screen reader accessible', async ({ page }) => {
    await page.goto('/admin/compliance/guidelines')
    await page.click('text=Create Guideline')

    // Check form labels
    const titleInput = page.locator('input#title')
    const label = page.locator('label[for="title"]')

    expect(await label.textContent()).toContain('Title')
    expect(await titleInput.getAttribute('aria-required')).toBe('true')
  })
})
```

---

## Resources

### Official Guidelines
- [WCAG 2.1 Quick Reference](https://www.w3.org/WAI/WCAG21/quickref/)
- [ARIA Authoring Practices Guide](https://www.w3.org/WAI/ARIA/apg/)
- [WebAIM Articles](https://webaim.org/articles/)

### Tools
- [axe DevTools](https://www.deque.com/axe/devtools/) - Browser extension
- [WAVE](https://wave.webaim.org/) - Browser extension
- [Color Contrast Checker](https://webaim.org/resources/contrastchecker/)
- [Screen Reader Testing](https://www.nvaccess.org/) - NVDA (free)

### Testing
- [Pa11y CI](https://github.com/pa11y/pa11y-ci) - Automated accessibility testing
- [axe-playwright](https://github.com/abhinaba-ghosh/axe-playwright) - Playwright integration
- [jest-axe](https://github.com/nickcolley/jest-axe) - Jest integration

---

## Quick Reference: ARIA Roles & Attributes

### Common ARIA Roles
```
role="button"         - Interactive button
role="link"           - Hyperlink
role="dialog"         - Modal dialog
role="menu"           - Menu container
role="menuitem"       - Item in menu
role="tab"            - Tab in tablist
role="tabpanel"       - Content for tab
role="alert"          - Important message
role="status"         - Status update
```

### Common ARIA Attributes
```
aria-label            - Accessible name
aria-labelledby       - Points to element with label
aria-describedby      - Points to description
aria-required         - Required field
aria-invalid          - Validation error
aria-expanded         - Expanded/collapsed state
aria-haspopup         - Has popup/menu
aria-controls         - Controls another element
aria-live             - Live region (polite/assertive)
aria-hidden           - Hidden from screen readers
```

---

**Accessibility Testing Guide Complete** ✅

**Remember**: Accessibility is not optional. It's a requirement for every feature before production deployment.

**Questions?** Contact QA team or accessibility champion.

