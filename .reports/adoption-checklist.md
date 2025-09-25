# CoreFlow360 V4 - Design Token Adoption Checklist

## 🎯 Quick Start for Developers

This checklist ensures consistent token usage and smooth adoption across the CoreFlow360 V4 development team.

## ✅ Pre-Development Setup

### Environment Setup
- [ ] **Install dependencies** - Ensure your project has the latest token system files
- [ ] **Import tokens** - Verify `design-system/tokens.css` is imported in `globals.css`
- [ ] **Configure Tailwind** - Check `tailwind.config.js` includes token extensions
- [ ] **IDE Setup** - Install Tailwind CSS IntelliSense extension for autocomplete

### Token System Familiarization
- [ ] **Review token hierarchy** - Understand Global → Semantic → Component structure
- [ ] **Study refactored components** - Examine `*-refactored.tsx` files for patterns
- [ ] **Test build process** - Run `npm run build` to ensure token integration works

## 🔧 Component Development Rules

### ✅ ALWAYS DO

#### 1. Use Semantic Tokens First
```tsx
// ✅ CORRECT - Use semantic tokens
<div className="bg-surface border border-muted rounded-card p-component-lg">
  <h2 className="heading-3 text-primary">Title</h2>
  <p className="body-base text-secondary">Description</p>
</div>

// ✅ CORRECT - Use CSS variables in custom styles
.custom-component {
  background: var(--bg-surface);
  color: var(--text-primary);
  padding: var(--spacing-component-lg);
}
```

#### 2. Follow Component Patterns
```tsx
// ✅ CORRECT - Use refactored components
import { Button } from '@/components/ui/button-refactored'
import { Card } from '@/components/ui/card-refactored'

<Button variant="default" size="md">Save</Button>
<Card className="custom-spacing">Content</Card>
```

#### 3. Use 8px Grid System
- [ ] All spacing must be multiples of 8px
- [ ] Use component spacing tokens: `component-xs`, `component-sm`, `component-md`, `component-lg`, `component-xl`
- [ ] Use layout spacing tokens: `layout-xs`, `layout-sm`, `layout-md`, `layout-lg`, `layout-xl`

### ❌ NEVER DO

#### 1. Avoid Hardcoded Values
```tsx
// ❌ WRONG - Hardcoded colors
<div className="bg-blue-600 text-white border-gray-200">
  Content
</div>

// ❌ WRONG - Arbitrary spacing
<div className="p-7 m-13">
  Content
</div>

// ❌ WRONG - Inline styles with hardcoded values
<div style={{ backgroundColor: '#3b82f6', padding: '20px' }}>
  Content
</div>
```

#### 2. Don't Create New Variants Without Tokens
```tsx
// ❌ WRONG - Custom variant without semantic meaning
<Button className="bg-purple-500 hover:bg-purple-600">
  Custom Button
</Button>

// ✅ CORRECT - Extend component properly or use semantic tokens
<Button variant="default" className="bg-accent hover:bg-accent-hover">
  Custom Button
</Button>
```

## 🎨 Token Extension Guidelines

### Adding New Tokens

#### 1. Update design-tokens.json First
```json
{
  "semantic": {
    "colors": {
      "background": {
        "elevated": {
          "value": "{global.colors.white}",
          "type": "color",
          "description": "Elevated surfaces like popovers, tooltips"
        }
      }
    }
  }
}
```

#### 2. Regenerate CSS Variables
- Update `design-system/tokens.css` with new variables
- Add corresponding Tailwind mappings in `tailwind.tokens.cjs`

#### 3. Test New Tokens
```bash
# Test build passes
npm run build

# Validate token usage
npm run typecheck
```

### Adding New Component Tokens

#### 1. Follow Naming Convention
```json
{
  "component": {
    "button": {
      "padding": {
        "sm": {
          "value": "{semantic.spacing.component.xs}",
          "type": "spacing"
        }
      }
    }
  }
}
```

#### 2. Create Component Variants
```tsx
const componentVariants = cva(
  "base-classes",
  {
    variants: {
      size: {
        sm: "px-component-xs py-component-xs",
        md: "px-component-sm py-component-xs",
        lg: "px-component-md py-component-sm"
      }
    }
  }
)
```

## 🌙 Theme Support Rules

### Adding New Themes

#### 1. Extend Themes Section
```json
{
  "dark": {
    "colors": {
      "background": {
        "canvas": {
          "value": "{global.colors.gray.900}",
          "type": "color"
        }
      }
    }
  },
  "high-contrast": {
    "colors": {
      "background": {
        "canvas": {
          "value": "{global.colors.black}",
          "type": "color"
        }
      }
    }
  }
}
```

#### 2. Update CSS Theme Classes
```css
[data-theme="dark"] {
  --bg-canvas: var(--color-gray-900);
  --text-primary: var(--color-white);
}

[data-theme="high-contrast"] {
  --bg-canvas: var(--color-black);
  --text-primary: var(--color-white);
}
```

## 🧪 Token Validation Workflow

### Pre-Commit Checks
- [ ] **Build passes** - `npm run build` succeeds
- [ ] **Types valid** - `npm run typecheck` passes
- [ ] **Lint clean** - `npm run lint` passes
- [ ] **Tokens used correctly** - No hardcoded values in new code

### Token Validation Script
```bash
# Create custom validation script
npm run tokens:validate
```

### Manual Testing Checklist
- [ ] **Light/Dark themes** - Test component in both themes
- [ ] **Responsive behavior** - Check on different screen sizes
- [ ] **Component variants** - Test all size/variant combinations
- [ ] **Interactive states** - Verify hover, focus, active states

## ♿ Accessibility Requirements

### Color Contrast Rules
- [ ] **WCAG AA compliance** - Minimum 4.5:1 contrast for normal text
- [ ] **WCAG AA Large** - Minimum 3:1 contrast for large text (18px+)
- [ ] **Interactive elements** - Minimum 3:1 contrast for UI components

### Motion Sensitivity
```tsx
// ✅ CORRECT - Respect prefers-reduced-motion
<div className="transition-all duration-fast motion-reduce:transition-none">
  Animated content
</div>
```

```css
/* ✅ CORRECT - CSS approach */
@media (prefers-reduced-motion: reduce) {
  .animated-element {
    animation: none;
    transition: none;
  }
}
```

### Focus Management
- [ ] **Visible focus indicators** - Use `focus-ring` utility class
- [ ] **Keyboard navigation** - Ensure tab order is logical
- [ ] **Screen reader support** - Include appropriate ARIA labels

## 📋 Code Review Checklist

### For Reviewers
- [ ] **No hardcoded values** - Check for hex colors, arbitrary spacing
- [ ] **Semantic token usage** - Verify meaningful class names
- [ ] **Component consistency** - Uses established patterns
- [ ] **Theme compatibility** - Works in light/dark modes
- [ ] **Accessibility compliance** - Meets WCAG standards

### For Authors
- [ ] **Self-review completed** - Check against this checklist
- [ ] **Build tested locally** - Verify no compilation errors
- [ ] **Visual testing** - Check component appearance
- [ ] **Documentation updated** - Update Storybook if needed

## 🚀 Performance Considerations

### CSS Optimization
- [ ] **Purge unused classes** - Tailwind purges correctly
- [ ] **Token consolidation** - Avoid duplicate CSS variables
- [ ] **Critical CSS** - Ensure tokens load with critical styles

### Bundle Size
- [ ] **Tree shaking** - Unused token utilities are eliminated
- [ ] **Component imports** - Use specific component imports
- [ ] **CSS variables** - Efficient cascade without duplication

## 📚 Learning Resources

### Quick References
- **Token Mapping Guide** - See `refactor-plan.md` for before/after examples
- **Component Examples** - Study `*-refactored.tsx` files
- **Design System** - Review `design-tokens.json` structure

### External Resources
- [Tokens Studio Documentation](https://tokens.studio/)
- [Design Tokens W3C Spec](https://design-tokens.github.io/community-group/format/)
- [Tailwind CSS Custom Properties](https://tailwindcss.com/docs/customizing-colors#using-css-variables)

## ⚠️ Common Pitfalls to Avoid

### 1. Token Mixing
```tsx
// ❌ WRONG - Mixing token systems
<div className="bg-surface p-4 text-gray-600">
  Mixed token usage
</div>

// ✅ CORRECT - Consistent token usage
<div className="bg-surface p-component-md text-secondary">
  Consistent token usage
</div>
```

### 2. Over-Customization
```tsx
// ❌ WRONG - Fighting the token system
<Button className="!bg-red-500 !text-white !p-6">
  Over-customized
</Button>

// ✅ CORRECT - Use appropriate variant or extend system
<Button variant="destructive" size="lg">
  Properly styled
</Button>
```

### 3. Ignoring Semantic Meaning
```tsx
// ❌ WRONG - Using accent color for errors
<div className="bg-accent text-inverse">
  Error message
</div>

// ✅ CORRECT - Use semantic error tokens
<div className="bg-error text-inverse">
  Error message
</div>
```

## 🎯 Success Metrics

### Developer Adoption
- [ ] 90%+ of new components use semantic tokens
- [ ] Zero hardcoded color values in new code
- [ ] Build time remains stable or improves
- [ ] CSS bundle size doesn't increase significantly

### Design Consistency
- [ ] All components follow 8px spacing grid
- [ ] Color usage aligns with semantic meanings
- [ ] Typography scale is consistently applied
- [ ] Accessibility standards are maintained

## 📞 Support & Questions

### Internal Resources
- **Design System Team** - Contact for token extension requests
- **Frontend Team Lead** - For architecture questions
- **Design Team** - For semantic token meanings

### Documentation
- **Refactor Plan** - `.reports/refactor-plan.md` for migration details
- **Figma Sync Guide** - `.reports/figma-sync-guide.md` for designer workflow
- **Component Examples** - See `frontend/src/components/ui/*-refactored.tsx`

---

## 📝 Adoption Tracking

### Team Member Completion
- [ ] **[Name]** - Completed token training
- [ ] **[Name]** - First component using tokens
- [ ] **[Name]** - Code review checklist internalized

### Project Milestones
- [ ] **Week 1** - All team members trained
- [ ] **Week 2** - First production components using tokens
- [ ] **Week 4** - 50% of new components use tokens
- [ ] **Week 8** - 90% token adoption achieved

---

*This checklist should be updated as the token system evolves. Last updated: 2025-09-24*