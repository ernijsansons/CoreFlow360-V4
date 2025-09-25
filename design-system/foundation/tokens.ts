/**
 * THE FUTURE OF ENTERPRISE - Design Tokens
 * Where enterprise software becomes art
 */

export const tokens = {
  // SPATIAL SYSTEM - 4px base unit with Fibonacci scaling
  spacing: {
    base: '4px',
    xs: '4px',     // 1 unit
    sm: '8px',     // 2 units
    md: '12px',    // 3 units
    lg: '20px',    // 5 units
    xl: '32px',    // 8 units
    '2xl': '52px', // 13 units
    '3xl': '84px', // 21 units

    // Golden ratio spacing
    golden: {
      sm: '0.618rem',  // 9.888px
      md: '1.618rem',  // 25.888px
      lg: '2.618rem',  // 41.888px
    }
  },

  // COLOR PHILOSOPHY - Monochrome with surgical precision
  colors: {
    // Base colors - absolute black and white
    black: '#000000',
    white: '#FFFFFF',

    // Grays - only 3 shades using opacity
    gray: {
      96: 'rgba(0, 0, 0, 0.04)',  // Barely visible
      64: 'rgba(0, 0, 0, 0.36)',  // Subtle
      24: 'rgba(0, 0, 0, 0.76)',  // Strong
    },

    // Single accent - Electric blue at 5% coverage max
    accent: {
      primary: '#0066FF',
      hover: '#0052CC',
      active: '#0047B3',
      muted: 'rgba(0, 102, 255, 0.05)',
      ghost: 'rgba(0, 102, 255, 0.02)',
    },

    // Semantic colors as tints
    semantic: {
      success: {
        base: '#00C851',
        light: 'rgba(0, 200, 81, 0.1)',
        text: 'rgba(0, 200, 81, 0.9)',
      },
      warning: {
        base: '#FFBB33',
        light: 'rgba(255, 187, 51, 0.1)',
        text: 'rgba(255, 187, 51, 0.9)',
      },
      error: {
        base: '#FF3547',
        light: 'rgba(255, 53, 71, 0.1)',
        text: 'rgba(255, 53, 71, 0.9)',
      },
    },

    // Dark mode first
    dark: {
      background: '#000000',
      surface: '#0A0A0A',
      elevated: '#141414',
      overlay: 'rgba(0, 0, 0, 0.8)',
      border: 'rgba(255, 255, 255, 0.08)',
      text: {
        primary: '#FFFFFF',
        secondary: 'rgba(255, 255, 255, 0.64)',
        tertiary: 'rgba(255, 255, 255, 0.36)',
      }
    },

    // Light mode as inversion
    light: {
      background: '#FFFFFF',
      surface: '#FAFAFA',
      elevated: '#F5F5F5',
      overlay: 'rgba(255, 255, 255, 0.8)',
      border: 'rgba(0, 0, 0, 0.08)',
      text: {
        primary: '#000000',
        secondary: 'rgba(0, 0, 0, 0.64)',
        tertiary: 'rgba(0, 0, 0, 0.36)',
      }
    }
  },

  // TYPOGRAPHY DNA - Precision and hierarchy
  typography: {
    fontFamily: {
      display: '-apple-system, "SF Pro Display", "Helvetica Neue", sans-serif',
      body: 'system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
      mono: '"SF Mono", "Monaco", "Inconsolata", monospace',
    },

    // Scale: 13/16/20/28/40/64px only
    fontSize: {
      xs: '13px',   // Small labels
      base: '16px', // Body text
      md: '20px',   // Subheadings
      lg: '28px',   // Headings
      xl: '40px',   // Display
      '2xl': '64px', // Hero
    },

    // Only 2 weights needed
    fontWeight: {
      regular: 400,
      medium: 500,
    },

    // Consistent leading
    lineHeight: {
      base: 1.5,
      tight: 1.2,  // For large display text
    },

    // Letter spacing for optical perfection
    letterSpacing: {
      tight: '-0.02em',
      normal: '0',
      wide: '0.02em',
    }
  },

  // MOTION DOCTRINE - Butter smooth, purposeful
  motion: {
    duration: {
      instant: '100ms',
      fast: '200ms',
      standard: '300ms',
      slow: '400ms',
      deliberate: '600ms',
    },

    easing: {
      // The One True Easing
      standard: 'cubic-bezier(0.4, 0, 0.2, 1)',
      // Variations for specific use cases
      accelerate: 'cubic-bezier(0.4, 0, 1, 1)',
      decelerate: 'cubic-bezier(0, 0, 0.2, 1)',
      bounce: 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
    },

    // Stagger delays for orchestrated animations
    stagger: {
      fast: '50ms',
      standard: '100ms',
      slow: '150ms',
    }
  },

  // DEPTH SYSTEM - Layering without shadows
  depth: {
    base: 0,
    raised: 1,
    elevated: 2,
    overlay: 3,
    modal: 4,
    popover: 5,
    tooltip: 6,
    notification: 7,
  },

  // BORDER SYSTEM - Barely there
  borders: {
    width: {
      thin: '1px',
      medium: '2px',
    },
    radius: {
      none: '0px',       // Sharp edges only
      minimal: '2px',    // Subtle softening when needed
      rounded: '4px',    // For buttons/inputs
      circular: '9999px', // For pills/avatars
    },
    color: {
      default: 'rgba(0, 0, 0, 0.08)',
      strong: 'rgba(0, 0, 0, 0.16)',
      interactive: 'rgba(0, 102, 255, 0.24)',
    }
  },

  // GRID SYSTEM - Mathematical precision
  grid: {
    columns: 12,
    gutter: '20px', // Fibonacci
    maxWidth: '1440px',
    breakpoints: {
      xs: '0px',
      sm: '640px',
      md: '768px',
      lg: '1024px',
      xl: '1280px',
      '2xl': '1536px',
    }
  },

  // COMPONENT TOKENS - Specific measurements
  components: {
    button: {
      height: {
        small: '32px',
        default: '40px',
        large: '48px',
      },
      padding: {
        small: '12px 20px',
        default: '16px 32px',
        large: '20px 40px',
      }
    },
    input: {
      height: '48px',
      padding: '12px 16px',
      borderWidth: '1px',
    },
    card: {
      padding: '20px',
      borderRadius: '0px',
    },
    commandBar: {
      height: '48px',
      width: '100%',
      padding: '0 20px',
    },
    table: {
      rowHeight: '48px',
      headerHeight: '40px',
      cellPadding: '12px 20px',
    }
  },

  // INTERACTION STATES - Consistent feedback
  states: {
    hover: {
      opacity: 0.8,
      scale: 1.02,
      duration: '200ms',
    },
    active: {
      opacity: 0.6,
      scale: 0.98,
      duration: '100ms',
    },
    disabled: {
      opacity: 0.3,
      cursor: 'not-allowed',
    },
    focus: {
      outline: '2px solid',
      outlineColor: '#0066FF',
      outlineOffset: '2px',
    }
  }
};

// Export individual token categories for tree-shaking
export const { spacing, colors, typography, motion, depth, borders, grid, components, states } = tokens;

// CSS Variables Generator
export const generateCSSVariables = (mode: 'light' | 'dark' = 'dark') => {
  const cssVars: Record<string, string> = {};

  // Spacing
  Object.entries(spacing).forEach(([key, value]) => {
    if (typeof value === 'string') {
      cssVars[`--space-${key}`] = value;
    }
  });

  // Colors based on mode
  const colorMode = mode === 'dark' ? colors.dark : colors.light;
  Object.entries(colorMode).forEach(([key, value]) => {
    if (typeof value === 'string') {
      cssVars[`--color-${key}`] = value;
    } else if (typeof value === 'object') {
      Object.entries(value).forEach(([subKey, subValue]) => {
        cssVars[`--color-${key}-${subKey}`] = subValue as string;
      });
    }
  });

  // Typography
  Object.entries(typography.fontSize).forEach(([key, value]) => {
    cssVars[`--font-size-${key}`] = value;
  });

  // Motion
  Object.entries(motion.duration).forEach(([key, value]) => {
    cssVars[`--duration-${key}`] = value;
  });

  Object.entries(motion.easing).forEach(([key, value]) => {
    cssVars[`--easing-${key}`] = value;
  });

  return cssVars;
};

export default tokens;