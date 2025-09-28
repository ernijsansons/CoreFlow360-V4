/**
 * CoreFlow360 V4 Design System
 * Mobile-first, accessible, and performant design tokens and utilities
 */

// Design Tokens
export const designTokens = {
  // Color System
  colors: {
    // Brand Colors
    brand: {
      primary: {
        50: '#eff6ff',
        100: '#dbeafe',
        200: '#bfdbfe',
        300: '#93c5fd',
        400: '#60a5fa',
        500: '#3b82f6',
        600: '#2563eb',
        700: '#1d4ed8',
        800: '#1e40af',
        900: '#1e3a8a',
      },
      secondary: {
        50: '#faf5ff',
        100: '#f3e8ff',
        200: '#e9d5ff',
        300: '#d8b4fe',
        400: '#c084fc',
        500: '#a855f7',
        600: '#9333ea',
        700: '#7e22ce',
        800: '#6b21a8',
        900: '#581c87',
      },
    },
    // Semantic Colors
    semantic: {
      success: {
        light: '#10b981',
        DEFAULT: '#059669',
        dark: '#047857',
      },
      warning: {
        light: '#fbbf24',
        DEFAULT: '#f59e0b',
        dark: '#d97706',
      },
      error: {
        light: '#f87171',
        DEFAULT: '#ef4444',
        dark: '#dc2626',
      },
      info: {
        light: '#60a5fa',
        DEFAULT: '#3b82f6',
        dark: '#2563eb',
      },
    },
    // Neutral Colors
    gray: {
      50: '#f9fafb',
      100: '#f3f4f6',
      200: '#e5e7eb',
      300: '#d1d5db',
      400: '#9ca3af',
      500: '#6b7280',
      600: '#4b5563',
      700: '#374151',
      800: '#1f2937',
      900: '#111827',
    },
  },

  // Typography System
  typography: {
    fontFamily: {
      sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
      mono: ['JetBrains Mono', 'Monaco', 'Consolas', 'monospace'],
    },
    fontSize: {
      xs: ['0.75rem', { lineHeight: '1rem' }],
      sm: ['0.875rem', { lineHeight: '1.25rem' }],
      base: ['1rem', { lineHeight: '1.5rem' }],
      lg: ['1.125rem', { lineHeight: '1.75rem' }],
      xl: ['1.25rem', { lineHeight: '1.75rem' }],
      '2xl': ['1.5rem', { lineHeight: '2rem' }],
      '3xl': ['1.875rem', { lineHeight: '2.25rem' }],
      '4xl': ['2.25rem', { lineHeight: '2.5rem' }],
      '5xl': ['3rem', { lineHeight: '1' }],
    },
    fontWeight: {
      thin: '100',
      extralight: '200',
      light: '300',
      normal: '400',
      medium: '500',
      semibold: '600',
      bold: '700',
      extrabold: '800',
      black: '900',
    },
  },

  // Spacing System
  spacing: {
    px: '1px',
    0: '0px',
    0.5: '0.125rem',
    1: '0.25rem',
    1.5: '0.375rem',
    2: '0.5rem',
    2.5: '0.625rem',
    3: '0.75rem',
    3.5: '0.875rem',
    4: '1rem',
    5: '1.25rem',
    6: '1.5rem',
    7: '1.75rem',
    8: '2rem',
    9: '2.25rem',
    10: '2.5rem',
    11: '2.75rem',
    12: '3rem',
    14: '3.5rem',
    16: '4rem',
    20: '5rem',
    24: '6rem',
    28: '7rem',
    32: '8rem',
    36: '9rem',
    40: '10rem',
    44: '11rem',
    48: '12rem',
    52: '13rem',
    56: '14rem',
    60: '15rem',
    64: '16rem',
    72: '18rem',
    80: '20rem',
    96: '24rem',
  },

  // Breakpoints (Mobile-First)
  breakpoints: {
    xs: '375px',   // Mobile S
    sm: '640px',   // Mobile L / Tablet
    md: '768px',   // Tablet
    lg: '1024px',  // Laptop
    xl: '1280px',  // Desktop
    '2xl': '1536px', // Large Desktop
  },

  // Border Radius
  borderRadius: {
    none: '0px',
    sm: '0.125rem',
    DEFAULT: '0.25rem',
    md: '0.375rem',
    lg: '0.5rem',
    xl: '0.75rem',
    '2xl': '1rem',
    '3xl': '1.5rem',
    full: '9999px',
  },

  // Shadows
  boxShadow: {
    sm: '0 1px 2px 0 rgb(0 0 0 / 0.05)',
    DEFAULT: '0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)',
    md: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
    lg: '0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)',
    xl: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)',
    '2xl': '0 25px 50px -12px rgb(0 0 0 / 0.25)',
    inner: 'inset 0 2px 4px 0 rgb(0 0 0 / 0.05)',
    none: 'none',
  },

  // Animation
  animation: {
    duration: {
      instant: '50ms',
      fast: '150ms',
      normal: '300ms',
      slow: '500ms',
      slower: '700ms',
    },
    easing: {
      linear: 'linear',
      in: 'cubic-bezier(0.4, 0, 1, 1)',
      out: 'cubic-bezier(0, 0, 0.2, 1)',
      inOut: 'cubic-bezier(0.4, 0, 0.2, 1)',
      bounce: 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
    },
  },

  // Z-Index Scale
  zIndex: {
    auto: 'auto',
    0: '0',
    10: '10',
    20: '20',
    30: '30',
    40: '40',
    50: '50',
    dropdown: '1000',
    sticky: '1020',
    fixed: '1030',
    modalBackdrop: '1040',
    modal: '1050',
    popover: '1060',
    tooltip: '1070',
  },
};

// Responsive Utilities
export const responsive = {
  isMobile: () => {
    if (typeof window === 'undefined') return false;
    return window.innerWidth < 768;
  },
  
  isTablet: () => {
    if (typeof window === 'undefined') return false;
    return window.innerWidth >= 768 && window.innerWidth < 1024;
  },
  
  isDesktop: () => {
    if (typeof window === 'undefined') return false;
    return window.innerWidth >= 1024;
  },
  
  getBreakpoint: () => {
    if (typeof window === 'undefined') return 'sm';
    const width = window.innerWidth;
    
    if (width < 640) return 'xs';
    if (width < 768) return 'sm';
    if (width < 1024) return 'md';
    if (width < 1280) return 'lg';
    if (width < 1536) return 'xl';
    return '2xl';
  },
};

// CSS-in-JS Helpers
export const css = {
  // Flexbox utilities
  flex: {
    center: 'display: flex; align-items: center; justify-content: center;',
    between: 'display: flex; align-items: center; justify-content: space-between;',
    start: 'display: flex; align-items: flex-start; justify-content: flex-start;',
    end: 'display: flex; align-items: flex-end; justify-content: flex-end;',
    column: 'display: flex; flex-direction: column;',
    wrap: 'display: flex; flex-wrap: wrap;',
  },
  
  // Grid utilities
  grid: {
    cols: (cols: number) => `display: grid; grid-template-columns: repeat(${cols}, minmax(0, 1fr));`,
    gap: (size: number) => `gap: ${size}rem;`,
    responsive: `
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1rem;
    `,
  },
  
  // Typography utilities
  text: {
    truncate: 'overflow: hidden; text-overflow: ellipsis; white-space: nowrap;',
    clamp: (lines: number) => `
      display: -webkit-box;
      -webkit-line-clamp: ${lines};
      -webkit-box-orient: vertical;
      overflow: hidden;
    `,
    gradient: (from: string, to: string) => `
      background: linear-gradient(to right, ${from}, ${to});
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    `,
  },
  
  // Transition utilities
  transition: {
    all: `transition: all ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};`,
    colors: `transition: background-color, border-color, color, fill, stroke ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};`,
    transform: `transition: transform ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};`,
    opacity: `transition: opacity ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};`,
  },
};

// Accessibility Utilities
export const a11y = {
  // Screen reader only
  srOnly: `
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
  `,
  
  // Focus visible
  focusRing: `
    outline: 2px solid transparent;
    outline-offset: 2px;
    &:focus-visible {
      outline: 2px solid ${designTokens.colors.brand.primary[500]};
      outline-offset: 2px;
    }
  `,
  
  // Reduced motion
  reducedMotion: `
    @media (prefers-reduced-motion: reduce) {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  `,
};

// Component Variants
export const variants = {
  button: {
    primary: `
      background: linear-gradient(to right, ${designTokens.colors.brand.primary[600]}, ${designTokens.colors.brand.secondary[600]});
      color: white;
      font-weight: 500;
      padding: 0.5rem 1rem;
      border-radius: ${designTokens.borderRadius.lg};
      transition: all ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};
      
      &:hover {
        transform: translateY(-1px);
        box-shadow: ${designTokens.boxShadow.lg};
      }
      
      &:active {
        transform: translateY(0);
      }
      
      &:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }
    `,
    
    secondary: `
      background: ${designTokens.colors.gray[100]};
      color: ${designTokens.colors.gray[900]};
      font-weight: 500;
      padding: 0.5rem 1rem;
      border: 1px solid ${designTokens.colors.gray[300]};
      border-radius: ${designTokens.borderRadius.lg};
      transition: all ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};
      
      &:hover {
        background: ${designTokens.colors.gray[200]};
      }
    `,
    
    ghost: `
      background: transparent;
      color: ${designTokens.colors.gray[700]};
      font-weight: 500;
      padding: 0.5rem 1rem;
      border-radius: ${designTokens.borderRadius.lg};
      transition: all ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};
      
      &:hover {
        background: ${designTokens.colors.gray[100]};
      }
    `,
  },
  
  card: {
    elevated: `
      background: white;
      border-radius: ${designTokens.borderRadius.xl};
      box-shadow: ${designTokens.boxShadow.lg};
      padding: 1.5rem;
      transition: all ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};
      
      &:hover {
        box-shadow: ${designTokens.boxShadow.xl};
        transform: translateY(-2px);
      }
    `,
    
    flat: `
      background: white;
      border: 1px solid ${designTokens.colors.gray[200]};
      border-radius: ${designTokens.borderRadius.xl};
      padding: 1.5rem;
      transition: all ${designTokens.animation.duration.normal} ${designTokens.animation.easing.inOut};
      
      &:hover {
        border-color: ${designTokens.colors.gray[300]};
      }
    `,
  },
};

// Export all as default
const designSystem = {
  tokens: designTokens,
  responsive,
  css,
  a11y,
  variants,
};

export default designSystem;