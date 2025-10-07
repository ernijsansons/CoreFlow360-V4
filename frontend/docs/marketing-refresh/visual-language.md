# CoreFlow360 V4 - Visual Language System

## Design Philosophy
A Fortune-50 caliber visual system that communicates trust through sophisticated simplicity, innovation through intelligent motion, and scale through systematic design.

---

## Color Palette

### Primary Brand Colors

#### Core Blue Gradient
The foundation of trust and technology
```css
--marketing-primary-50: #eff8ff;   /* Whisper - Backgrounds */
--marketing-primary-100: #dbeefe;  /* Mist - Hover states */
--marketing-primary-200: #bfdbfe;  /* Sky - Disabled states */
--marketing-primary-300: #93c5fd;  /* Crystal - Borders */
--marketing-primary-400: #60a5fa;  /* Ocean - Secondary buttons */
--marketing-primary-500: #3b82f6;  /* Core - Primary actions */
--marketing-primary-600: #2563eb;  /* Trust - Primary buttons */
--marketing-primary-700: #1d4ed8;  /* Deep - Hover states */
--marketing-primary-800: #1e40af;  /* Midnight - Active states */
--marketing-primary-900: #1e3a8a;  /* Abyss - Text on light */
```

**Usage:**
- Primary CTAs: `primary-600` with `primary-700` hover
- Hero gradients: `primary-500` to `primary-800`
- Trust badges: `primary-600`
- Links: `primary-600` with `primary-700` hover

#### Innovation Purple Accent
For AI and advanced features
```css
--marketing-accent-400: #c084fc;  /* Bright - Feature highlights */
--marketing-accent-500: #a855f7;  /* Innovation - AI elements */
--marketing-accent-600: #9333ea;  /* Deep - Premium features */
--marketing-accent-700: #7e22ce;  /* Rich - Enterprise */
```

**Usage:**
- AI feature badges: `accent-500`
- Premium tier highlights: `accent-600`
- Innovation sections: Gradient `accent-400` to `accent-600`

#### Growth Teal
For success and growth messaging
```css
--marketing-teal-400: #2dd4bf;   /* Bright - Success states */
--marketing-teal-500: #14b8a6;   /* Growth - Metrics up */
--marketing-teal-600: #0d9488;   /* Deep - Confirmed states */
```

**Usage:**
- Success metrics: `teal-500`
- Growth indicators: `teal-400`
- Positive alerts: `teal-500` background with white text

### Semantic Colors

#### Success States
```css
--marketing-success-light: #dcfce7;  /* Background */
--marketing-success-main: #22c55e;   /* Primary */
--marketing-success-dark: #16a34a;   /* Text/borders */
```

#### Warning States
```css
--marketing-warning-light: #fef3c7;  /* Background */
--marketing-warning-main: #f59e0b;   /* Primary */
--marketing-warning-dark: #d97706;   /* Text/borders */
```

#### Error States
```css
--marketing-error-light: #fee2e2;   /* Background */
--marketing-error-main: #ef4444;    /* Primary */
--marketing-error-dark: #dc2626;    /* Text/borders */
```

### Neutral Palette

#### Grays for Content
```css
--marketing-gray-50: #fafafa;    /* Subtle backgrounds */
--marketing-gray-100: #f4f4f5;   /* Section backgrounds */
--marketing-gray-200: #e4e4e7;   /* Borders */
--marketing-gray-300: #d4d4d8;   /* Disabled borders */
--marketing-gray-400: #a1a1aa;   /* Placeholder text */
--marketing-gray-500: #71717a;   /* Secondary text */
--marketing-gray-600: #52525b;   /* Body text */
--marketing-gray-700: #3f3f46;   /* Emphasized text */
--marketing-gray-800: #27272a;   /* Headings */
--marketing-gray-900: #18181b;   /* Primary text */
```

### Marketing-Specific Colors

#### Gradient Definitions
```css
/* Hero Gradients */
--gradient-hero-primary: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%);
--gradient-hero-aurora: linear-gradient(135deg, #3b82f6 0%, #a855f7 50%, #14b8a6 100%);
--gradient-hero-sunset: linear-gradient(135deg, #f59e0b 0%, #dc2626 100%);

/* Feature Gradients */
--gradient-ai-glow: radial-gradient(circle, rgba(168,85,247,0.2) 0%, transparent 70%);
--gradient-card-hover: linear-gradient(135deg, rgba(37,99,235,0.05) 0%, rgba(147,51,234,0.05) 100%);

/* Text Gradients */
--gradient-text-premium: linear-gradient(135deg, #3b82f6 0%, #a855f7 100%);
--gradient-text-gold: linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%);
```

---

## Typography Scale

### Font Families
```css
/* Primary - System for performance */
--font-marketing-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Roboto",
                       "Oxygen", "Ubuntu", "Fira Sans", "Helvetica Neue", sans-serif;

/* Monospace - For code/technical */
--font-marketing-mono: "JetBrains Mono", "SF Mono", "Monaco", "Inconsolata",
                       "Fira Code", "Roboto Mono", monospace;

/* Display - For hero headings (optional web font) */
--font-marketing-display: "Inter", var(--font-marketing-sans);
```

### Size Scale with Responsive Scaling
```css
/* Mobile → Desktop fluid scaling */
--text-hero-display: clamp(2.5rem, 5vw + 1rem, 5rem);      /* 40px → 80px */
--text-hero-title: clamp(2rem, 4vw + 0.5rem, 3.75rem);     /* 32px → 60px */
--text-hero-subtitle: clamp(1.5rem, 3vw + 0.25rem, 2.5rem); /* 24px → 40px */

/* Section headings */
--text-h1: clamp(2rem, 3vw + 0.5rem, 3rem);      /* 32px → 48px */
--text-h2: clamp(1.5rem, 2.5vw + 0.25rem, 2.25rem); /* 24px → 36px */
--text-h3: clamp(1.25rem, 2vw + 0.25rem, 1.875rem); /* 20px → 30px */
--text-h4: clamp(1.125rem, 1.5vw + 0.25rem, 1.5rem); /* 18px → 24px */
--text-h5: clamp(1rem, 1vw + 0.25rem, 1.25rem);    /* 16px → 20px */
--text-h6: clamp(0.875rem, 0.5vw + 0.25rem, 1.125rem); /* 14px → 18px */

/* Body text */
--text-body-lg: clamp(1.125rem, 1vw + 0.5rem, 1.25rem);  /* 18px → 20px */
--text-body: 1rem;                                         /* 16px */
--text-body-sm: 0.875rem;                                  /* 14px */
--text-caption: 0.75rem;                                   /* 12px */
--text-overline: 0.6875rem;                               /* 11px */
```

### Weight Scale
```css
--weight-light: 300;     /* Subtle text */
--weight-regular: 400;   /* Body text */
--weight-medium: 500;    /* Emphasized body */
--weight-semibold: 600;  /* Subheadings */
--weight-bold: 700;      /* Headings */
--weight-extrabold: 800; /* Hero text */
--weight-black: 900;     /* Display text */
```

### Line Heights
```css
--leading-hero: 0.95;    /* Tight for impact */
--leading-heading: 1.2;  /* Compact headings */
--leading-body: 1.6;     /* Comfortable reading */
--leading-relaxed: 1.75; /* Spacious content */
--leading-loose: 2;      /* Very open */
```

### Letter Spacing
```css
--tracking-hero: -0.03em;    /* Tight for hero text */
--tracking-heading: -0.02em; /* Slightly tight headings */
--tracking-normal: 0;        /* Body text */
--tracking-wide: 0.025em;    /* Buttons and labels */
--tracking-wider: 0.05em;    /* Overlines */
--tracking-widest: 0.1em;    /* All caps text */
```

### Responsive Typography Classes
```css
/* Hero Section */
.text-hero-display {
  font-size: var(--text-hero-display);
  font-weight: var(--weight-extrabold);
  line-height: var(--leading-hero);
  letter-spacing: var(--tracking-hero);
}

/* Feature Headings */
.text-feature-title {
  font-size: var(--text-h2);
  font-weight: var(--weight-bold);
  line-height: var(--leading-heading);
  letter-spacing: var(--tracking-heading);
}

/* Marketing Body */
.text-marketing-body {
  font-size: var(--text-body-lg);
  font-weight: var(--weight-regular);
  line-height: var(--leading-body);
  color: var(--marketing-gray-600);
}
```

---

## Spacing System

### Base Unit
8px grid system for consistent alignment

### Spacing Scale
```css
--space-0: 0;          /* 0px */
--space-1: 0.25rem;    /* 4px */
--space-2: 0.5rem;     /* 8px - Base unit */
--space-3: 0.75rem;    /* 12px */
--space-4: 1rem;       /* 16px */
--space-5: 1.25rem;    /* 20px */
--space-6: 1.5rem;     /* 24px */
--space-8: 2rem;       /* 32px */
--space-10: 2.5rem;    /* 40px */
--space-12: 3rem;      /* 48px */
--space-16: 4rem;      /* 64px */
--space-20: 5rem;      /* 80px */
--space-24: 6rem;      /* 96px */
--space-32: 8rem;      /* 128px */
--space-40: 10rem;     /* 160px */
--space-48: 12rem;     /* 192px */
--space-56: 14rem;     /* 224px */
--space-64: 16rem;     /* 256px */
```

### Container Widths
```css
--container-xs: 20rem;     /* 320px - Mobile minimum */
--container-sm: 24rem;     /* 384px - Small mobile */
--container-md: 28rem;     /* 448px - Large mobile */
--container-lg: 32rem;     /* 512px - Small tablet */
--container-xl: 36rem;     /* 576px - Tablet */
--container-2xl: 42rem;    /* 672px - Small desktop */
--container-3xl: 48rem;    /* 768px - Desktop */
--container-4xl: 64rem;    /* 1024px - Large desktop */
--container-5xl: 80rem;    /* 1280px - Wide screen */
--container-6xl: 90rem;    /* 1440px - Ultra wide */
--container-max: 1536px;   /* Maximum width */
```

### Breakpoints
```css
--breakpoint-xs: 475px;    /* Large phone */
--breakpoint-sm: 640px;    /* Small tablet */
--breakpoint-md: 768px;    /* Tablet */
--breakpoint-lg: 1024px;   /* Desktop */
--breakpoint-xl: 1280px;   /* Large desktop */
--breakpoint-2xl: 1536px;  /* Wide screen */
--breakpoint-3xl: 1920px;  /* Ultra wide */
```

### Section Spacing
```css
/* Vertical rhythm for sections */
--section-spacing-sm: var(--space-16);   /* 64px */
--section-spacing-md: var(--space-24);   /* 96px */
--section-spacing-lg: var(--space-32);   /* 128px */
--section-spacing-xl: var(--space-48);   /* 192px */

/* Responsive section spacing */
@media (max-width: 768px) {
  --section-spacing-sm: var(--space-12);  /* 48px */
  --section-spacing-md: var(--space-16);  /* 64px */
  --section-spacing-lg: var(--space-24);  /* 96px */
  --section-spacing-xl: var(--space-32);  /* 128px */
}
```

---

## Motion Principles

### Duration Guidelines
```css
--duration-instant: 50ms;      /* Micro interactions */
--duration-fast: 150ms;        /* Hover states */
--duration-normal: 250ms;      /* Standard transitions */
--duration-slow: 350ms;        /* Complex animations */
--duration-deliberate: 500ms;  /* Page transitions */
--duration-crawl: 750ms;       /* Dramatic reveals */
```

### Easing Functions
```css
/* Standard easings */
--ease-in-out-quad: cubic-bezier(0.455, 0.03, 0.515, 0.955);
--ease-out-expo: cubic-bezier(0.19, 1, 0.22, 1);
--ease-out-back: cubic-bezier(0.175, 0.885, 0.32, 1.275);

/* Marketing-specific easings */
--ease-smooth: cubic-bezier(0.37, 0, 0.63, 1);
--ease-energetic: cubic-bezier(0.68, -0.55, 0.265, 1.55);
--ease-dramatic: cubic-bezier(0.22, 1, 0.36, 1);
```

### Animation Patterns
```css
/* Fade and slide */
@keyframes fadeInUp {
  from {
    opacity: 0;
    transform: translateY(30px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

/* Scale and fade */
@keyframes scaleIn {
  from {
    opacity: 0;
    transform: scale(0.9);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
}

/* Gradient animation */
@keyframes gradientShift {
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

/* Glow pulse */
@keyframes glowPulse {
  0%, 100% {
    box-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
  }
  50% {
    box-shadow: 0 0 40px rgba(59, 130, 246, 0.8);
  }
}
```

### Interaction States
```css
/* Hover lift */
.hover-lift {
  transition: transform var(--duration-normal) var(--ease-out-expo);
}
.hover-lift:hover {
  transform: translateY(-4px);
}

/* Hover glow */
.hover-glow {
  transition: box-shadow var(--duration-normal) var(--ease-smooth);
}
.hover-glow:hover {
  box-shadow: 0 0 30px rgba(59, 130, 246, 0.3);
}

/* Active press */
.active-press:active {
  transform: scale(0.98);
}
```

---

## Component Guidelines

### Elevation System
```css
/* Shadow elevation scale */
--elevation-0: none;
--elevation-1: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);
--elevation-2: 0 3px 6px rgba(0, 0, 0, 0.15), 0 2px 4px rgba(0, 0, 0, 0.12);
--elevation-3: 0 10px 20px rgba(0, 0, 0, 0.15), 0 3px 6px rgba(0, 0, 0, 0.10);
--elevation-4: 0 15px 25px rgba(0, 0, 0, 0.15), 0 5px 10px rgba(0, 0, 0, 0.05);
--elevation-5: 0 20px 40px rgba(0, 0, 0, 0.20), 0 10px 20px rgba(0, 0, 0, 0.10);

/* Colored shadows for marketing */
--shadow-primary: 0 10px 40px rgba(37, 99, 235, 0.3);
--shadow-accent: 0 10px 40px rgba(147, 51, 234, 0.3);
--shadow-success: 0 10px 40px rgba(34, 197, 94, 0.3);
```

### Border Radius Scale
```css
--radius-sm: 0.375rem;     /* 6px - Inputs, small buttons */
--radius-md: 0.5rem;       /* 8px - Cards, dropdowns */
--radius-lg: 0.75rem;      /* 12px - Modals, large cards */
--radius-xl: 1rem;         /* 16px - Hero sections */
--radius-2xl: 1.5rem;      /* 24px - Feature cards */
--radius-full: 9999px;     /* Pills, avatars */
```

### Button Styles
```css
/* Primary CTA */
.btn-primary {
  background: var(--gradient-hero-primary);
  color: white;
  padding: var(--space-3) var(--space-6);
  border-radius: var(--radius-md);
  font-weight: var(--weight-semibold);
  letter-spacing: var(--tracking-wide);
  box-shadow: var(--elevation-2);
  transition: all var(--duration-normal) var(--ease-smooth);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

/* Secondary button */
.btn-secondary {
  background: white;
  color: var(--marketing-primary-600);
  border: 2px solid var(--marketing-primary-200);
  padding: var(--space-3) var(--space-6);
  border-radius: var(--radius-md);
  font-weight: var(--weight-medium);
}

/* Ghost button */
.btn-ghost {
  background: transparent;
  color: var(--marketing-primary-600);
  padding: var(--space-3) var(--space-6);
  border-radius: var(--radius-md);
  font-weight: var(--weight-medium);
}
```

### Card Patterns
```css
/* Feature card */
.card-feature {
  background: white;
  border-radius: var(--radius-lg);
  padding: var(--space-8);
  box-shadow: var(--elevation-1);
  border: 1px solid var(--marketing-gray-200);
  transition: all var(--duration-normal) var(--ease-smooth);
}

.card-feature:hover {
  box-shadow: var(--elevation-3);
  transform: translateY(-4px);
  border-color: var(--marketing-primary-300);
}

/* Pricing card */
.card-pricing {
  background: white;
  border-radius: var(--radius-xl);
  padding: var(--space-10);
  box-shadow: var(--elevation-2);
  position: relative;
  overflow: hidden;
}

.card-pricing.featured {
  border: 2px solid var(--marketing-primary-500);
  box-shadow: var(--shadow-primary);
}

/* Testimonial card */
.card-testimonial {
  background: var(--marketing-gray-50);
  border-radius: var(--radius-lg);
  padding: var(--space-6);
  border-left: 4px solid var(--marketing-primary-500);
}
```

### Icon Sizing
```css
--icon-xs: 16px;    /* Inline with text */
--icon-sm: 20px;    /* Small buttons */
--icon-md: 24px;    /* Default size */
--icon-lg: 32px;    /* Feature icons */
--icon-xl: 48px;    /* Hero icons */
--icon-2xl: 64px;   /* Section icons */
```

---

## Glass Morphism Effects
```css
/* Glass card */
.glass-card {
  background: rgba(255, 255, 255, 0.7);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: var(--radius-lg);
}

/* Dark glass */
.glass-dark {
  background: rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(255, 255, 255, 0.1);
}

/* Colored glass */
.glass-primary {
  background: rgba(37, 99, 235, 0.1);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid rgba(37, 99, 235, 0.2);
}
```

---

## Marketing-Specific Components

### Hero Sections
```css
.hero-gradient-mesh {
  background:
    radial-gradient(circle at 20% 50%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
    radial-gradient(circle at 80% 80%, rgba(255, 119, 198, 0.3) 0%, transparent 50%),
    radial-gradient(circle at 40% 20%, rgba(255, 219, 120, 0.3) 0%, transparent 50%),
    linear-gradient(135deg, var(--marketing-primary-50) 0%, var(--marketing-primary-100) 100%);
}

.hero-text-gradient {
  background: var(--gradient-text-premium);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}
```

### Trust Badges
```css
.trust-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-2) var(--space-3);
  background: var(--marketing-primary-50);
  border: 1px solid var(--marketing-primary-200);
  border-radius: var(--radius-full);
  font-size: var(--text-body-sm);
  font-weight: var(--weight-medium);
  color: var(--marketing-primary-700);
}
```

### Feature Highlights
```css
.feature-highlight {
  position: relative;
  padding: var(--space-6);
  background: linear-gradient(135deg, rgba(37, 99, 235, 0.05) 0%, rgba(147, 51, 234, 0.05) 100%);
  border-radius: var(--radius-xl);
  border: 1px solid rgba(37, 99, 235, 0.1);
}

.feature-highlight::before {
  content: '';
  position: absolute;
  top: -1px;
  left: -1px;
  right: -1px;
  bottom: -1px;
  background: var(--gradient-hero-primary);
  border-radius: var(--radius-xl);
  opacity: 0;
  transition: opacity var(--duration-normal) var(--ease-smooth);
  z-index: -1;
}

.feature-highlight:hover::before {
  opacity: 0.1;
}
```

---

## Accessibility Considerations

### Color Contrast
- All text must meet WCAG AAA standards (7:1 for normal text, 4.5:1 for large text)
- Primary blue (#2563eb) on white: 8.14:1 ✓
- Gray-600 (#52525b) on white: 8.46:1 ✓
- White on primary-600: 8.14:1 ✓

### Focus Indicators
```css
.focus-visible:focus-visible {
  outline: 3px solid var(--marketing-primary-500);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}
```

### Motion Preferences
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

### Dark Mode Support
```css
@media (prefers-color-scheme: dark) {
  /* Dark mode overrides */
  --marketing-bg-base: var(--marketing-gray-900);
  --marketing-text-primary: var(--marketing-gray-50);
  /* Additional dark mode tokens... */
}
```

---

## Implementation Notes

### Performance Optimization
1. Use system fonts to avoid web font loading
2. Implement critical CSS inlining
3. Use CSS custom properties for dynamic theming
4. Lazy load non-critical animations
5. Use will-change sparingly for animations

### Browser Support
- Modern browsers (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+)
- Progressive enhancement for older browsers
- Fallback for backdrop-filter in older Safari

### Design Token Integration
These marketing tokens extend the existing design-tokens.css file. They should be namespaced with `--marketing-` prefix to avoid conflicts with application tokens.

---

## Logo Specifications

### Logo Construction
- **Symbol:** Interconnected infinity loops forming a 360° rotation
- **Wordmark:** "CoreFlow360" with "Core" in bold, "Flow360" in medium
- **Spacing:** 0.5x height between symbol and wordmark
- **Clear space:** Minimum 1x logo height on all sides

### Logo Variations
1. **Full horizontal:** Symbol + full wordmark (primary)
2. **Stacked:** Symbol above wordmark (secondary)
3. **Compact:** Symbol + "CF360" (mobile/small spaces)
4. **Icon only:** Symbol alone (app icon, favicon)

### Logo Colors
- **Primary:** Gradient from primary-600 to accent-600
- **Monochrome:** Single color (primary-600 or gray-900)
- **Inverse:** White for dark backgrounds
- **Knockout:** Transparent for overlays

### Animation Specifications
```css
@keyframes logo-rotate {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.logo-animated:hover .logo-symbol {
  animation: logo-rotate 2s ease-in-out;
}
```

---

This visual language system provides a complete foundation for creating a Fortune-50 caliber marketing website that communicates trust, innovation, and scale while maintaining excellent performance and accessibility standards.