# Figma Implementation Guide - The Future of Enterprise

## Overview

This guide explains how to implement the revolutionary enterprise design system in Figma using the Dev Mode MCP Server for seamless design-to-code workflow.

## Figma Structure

```
The Future of Enterprise (Figma File)
├── 📐 Foundations
│   ├── Colors
│   ├── Typography
│   ├── Spacing
│   └── Effects
├── 🧩 Components
│   ├── Primitives
│   ├── Signature Interfaces
│   └── Mobile Components
├── 📱 Screens
│   ├── Desktop
│   ├── Mobile
│   └── Tablet
└── 🎬 Prototypes
```

## Setting Up Design Tokens in Figma

### 1. Color System

Create these color styles in Figma:

```
Foundation/Black         → #000000
Foundation/White         → #FFFFFF

Gray/4                  → #000000 @ 4% opacity
Gray/8                  → #000000 @ 8% opacity
Gray/36                 → #000000 @ 36% opacity
Gray/64                 → #000000 @ 64% opacity
Gray/76                 → #000000 @ 76% opacity

Accent/Primary          → #0066FF
Accent/Hover           → #0052CC
Accent/Active          → #0047B3
Accent/Muted           → #0066FF @ 5% opacity

Semantic/Success        → #00C851
Semantic/Warning        → #FFBB33
Semantic/Error          → #FF3547
```

### 2. Typography Styles

```
Display/Hero            → 64px / 500 / 1.2
Display/Large           → 40px / 500 / 1.2
Heading/Default         → 28px / 500 / 1.3
Subheading/Default      → 20px / 400 / 1.4
Body/Default            → 16px / 400 / 1.5
Caption/Default         → 13px / 400 / 1.5
```

### 3. Effect Styles

```
Elevation/Raised        → No shadow (use borders)
Border/Default          → Inside 1px #000000 @ 8%
Border/Interactive      → Inside 1px #0066FF @ 24%
```

### 4. Spacing System

Use Auto Layout with these values:
```
4px   - Minimum unit
8px   - Tight spacing
12px  - Small spacing
20px  - Default spacing
32px  - Large spacing
52px  - Extra large
84px  - Maximum spacing
```

## Component Architecture

### Base Component Structure

Every component should follow this structure:

```
Component
├── .Base (Default variant)
├── .Hover
├── .Active
├── .Disabled
└── .Focus (for inputs)
```

### Creating the Button Component

1. **Frame Setup**
   - Width: Hug contents
   - Height: 40px (default) or 32px (small)
   - Auto Layout: Horizontal, center aligned
   - Padding: 16px horizontal, 0px vertical

2. **Variants**
   ```
   Property 1: Variant
   - Primary (Black bg, White text)
   - Secondary (Transparent bg, 1px border)
   - Ghost (Transparent bg, no border)

   Property 2: Size
   - Default (40px height)
   - Small (32px height)

   Property 3: State
   - Default
   - Hover (102% scale in prototype)
   - Active (98% scale)
   - Disabled (30% opacity)
   ```

3. **Interactive Components**
   - While hovering → Change to Hover variant
   - While pressing → Change to Active variant

### Creating the Command Bar

1. **Container**
   - Width: Fill (max 640px)
   - Height: 48px minimum
   - Background: White with 95% opacity
   - Backdrop blur: 20px

2. **Search Input**
   - Icon: Search (16x16)
   - Input text: 16px
   - Placeholder: "Type '/' for commands..."

3. **Suggestions List**
   - Max height: 384px
   - Item height: 48px
   - Hover state: Background #000000 @ 2%

### Creating the Data Table

1. **Table Structure**
   - Header height: 40px
   - Row height: 48px
   - Column padding: 20px
   - Border: Bottom only, 1px @ 4% opacity

2. **Interactive States**
   - Row hover: Background @ 2% opacity
   - Row selected: Blue accent @ 4% opacity
   - Sort indicators: Animated arrows

### Creating the Pipeline Component

1. **Stage Cards**
   - Width: 280px minimum
   - Auto Layout: Vertical
   - Gap: 12px between deals

2. **Deal Cards**
   - Height: Auto (min 80px)
   - Padding: 16px
   - Progress bar: Bottom border with % width

3. **Drag Interactions**
   - On drag: 105% scale, 2° rotation
   - Drop zones: Highlight with blue @ 2%

## Mobile Adaptations

### Breakpoints
```
Mobile:  375px (iPhone size)
Tablet:  768px (iPad portrait)
Desktop: 1440px (Standard desktop)
```

### Mobile Components

1. **Bottom Navigation**
   - Height: 64px + safe area
   - Icons: 20x20px
   - Active indicator: Filled background

2. **Mobile Cards**
   - Full width minus 32px padding
   - Touch target: Minimum 44px
   - Swipe actions: Show on drag

3. **Bottom Sheet**
   - Snap points: 50% and 90% of screen
   - Handle: 48x4px rounded bar
   - Backdrop: 50% black opacity

## Figma to Code Workflow

### 1. Using Dev Mode

Enable Dev Mode in Figma:
```
1. Open your design file
2. Toggle "Dev Mode" in top-right
3. Select any component
4. Code panel shows on right
```

### 2. MCP Server Commands

With Figma MCP Server connected:

```typescript
// Get component code
#get_code
// Returns React component with Tailwind classes

// Get design tokens
#get_variables
// Returns all color, spacing, typography tokens

// Get component image
#get_image
// Returns PNG of selected frame
```

### 3. Code Generation Examples

**Button Component:**
```tsx
// Selected in Figma → Generated via MCP
<button className="
  inline-flex items-center justify-center
  h-10 px-8
  bg-black text-white
  hover:scale-[1.02] active:scale-[0.98]
  transition-all duration-200
">
  Button Text
</button>
```

**Card Component:**
```tsx
// Selected in Figma → Generated via MCP
<div className="
  p-5
  bg-white dark:bg-black
  border border-black/8 dark:border-white/8
  hover:-translate-y-1
  transition-transform duration-200
">
  Card Content
</div>
```

## Design Handoff Checklist

### For Designers

- [ ] All components use Auto Layout
- [ ] Color styles applied (not hardcoded)
- [ ] Text styles applied (not custom)
- [ ] Interactive states defined
- [ ] Components properly named
- [ ] Variants structured logically
- [ ] Responsive behavior documented

### For Developers

- [ ] Dev Mode enabled
- [ ] MCP Server connected
- [ ] Design tokens exported
- [ ] Component code generated
- [ ] Interactions mapped
- [ ] Responsive breakpoints verified
- [ ] Accessibility annotations reviewed

## Best Practices

### 1. Component Naming
```
✅ Button/Primary/Default
✅ Card/Interactive/Hover
✅ Input/Email/Error

❌ Rectangle 123
❌ Group 45
❌ Component Copy
```

### 2. Layer Organization
```
Component
├── 📦 Content
│   ├── 🔤 Label
│   └── 🎨 Icon
├── 🎭 States
│   ├── Default
│   └── Hover
└── 📐 Spacing
```

### 3. Using Tokens
Always use design tokens instead of hardcoded values:
```
✅ Fill: Foundation/Black
✅ Effect: Border/Default
✅ Spacing: 20px (from scale)

❌ Fill: #000000
❌ Effect: Custom stroke
❌ Spacing: 23px (random)
```

## Figma Plugins Recommended

1. **Design Tokens** - Export tokens to code
2. **Figma to Code** - Advanced code generation
3. **Contrast** - Accessibility checking
4. **Figmotion** - Animation previews
5. **Able** - Accessibility annotations

## Prototyping Interactions

### Micro-interactions
```
Hover States:
- Trigger: While hovering
- Action: Change to hover variant
- Animation: Smart animate, 200ms

Click States:
- Trigger: While pressing
- Action: Scale 98%
- Animation: Spring, 200ms
```

### Page Transitions
```
Navigation:
- Trigger: On tap
- Action: Navigate to
- Animation: Smart animate, 300ms
- Direction: Based on hierarchy
```

### Gesture Support
```
Swipe Actions:
- Trigger: On drag
- Direction: Left/Right
- Action: Show action buttons
- Threshold: 80px
```

## Performance Guidelines

### Asset Optimization
- Export images at 2x for retina
- Use WebP format when possible
- Compress SVGs
- Lazy load below-fold images

### Component Efficiency
- Maximum 3 levels of nesting
- Use instances, not copies
- Detach only when necessary
- Keep file size under 100MB

## Accessibility in Figma

### Annotations
Add accessibility notes as comments:
```
- Role: button
- Label: "Save document"
- Keyboard: Space/Enter to activate
- Focus: 2px blue outline
```

### Color Contrast
Ensure WCAG AA compliance:
```
Text on Background:
- Normal text: 4.5:1 minimum
- Large text: 3:1 minimum
- Icons: 3:1 minimum
```

## Export Settings

### For Development
```
Format: SVG (for icons)
Format: PNG 2x (for images)
Format: PDF (for documentation)

Export settings:
- Include "id" attributes
- Outline text
- Include backgrounds
```

### Design Tokens Export
```json
{
  "colors": {
    "black": "#000000",
    "white": "#FFFFFF",
    "accent": "#0066FF"
  },
  "spacing": {
    "xs": "4px",
    "sm": "8px",
    "md": "20px",
    "lg": "32px",
    "xl": "52px"
  },
  "typography": {
    "hero": {
      "size": "64px",
      "weight": "500",
      "leading": "1.2"
    }
  }
}
```

## Troubleshooting

### MCP Server Issues
```
Issue: Components not generating code
Solution: Ensure Dev Mode is ON and frame is selected

Issue: Tokens not exporting
Solution: Check that styles are properly applied

Issue: Code doesn't match design
Solution: Verify Auto Layout settings match code
```

### Performance Issues
```
Issue: Figma file slow
Solution:
- Component instances instead of copies
- Reduce image sizes
- Archive old iterations

Issue: Prototype laggy
Solution:
- Simplify animations
- Reduce simultaneous transitions
- Use dissolve instead of smart animate
```

## Conclusion

This design system in Figma provides a complete foundation for building enterprise software that doesn't just function—it inspires. With proper implementation and the MCP Server connection, the design-to-code workflow becomes seamless, maintaining perfect fidelity from concept to production.

Remember: Every component in Figma should be production-ready code. Every interaction should be implementable. Every pixel should have purpose.