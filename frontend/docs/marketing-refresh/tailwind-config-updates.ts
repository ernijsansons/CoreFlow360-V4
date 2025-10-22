/**
 * Tailwind Configuration Updates for Marketing Refresh
 *
 * These updates should be merged into the existing tailwind.config.ts
 * They provide marketing-specific tokens that extend the core design system
 */

export const marketingThemeExtensions = {
  colors: {
    // Marketing-specific color palette
    marketing: {
      // Primary blues for trust and technology
      primary: {
        50: '#eff8ff',
        100: '#dbeefe',
        200: '#bfdbfe',
        300: '#93c5fd',
        400: '#60a5fa',
        500: '#3b82f6',
        600: '#2563eb', // Main CTA color
        700: '#1d4ed8',
        800: '#1e40af',
        900: '#1e3a8a',
        950: '#172554',
      },
      // Innovation purple for AI features
      accent: {
        50: '#faf5ff',
        100: '#f3e8ff',
        200: '#e9d5ff',
        300: '#d8b4fe',
        400: '#c084fc',
        500: '#a855f7', // AI highlight
        600: '#9333ea',
        700: '#7e22ce',
        800: '#6b21a8',
        900: '#581c87',
        950: '#3b0764',
      },
      // Growth teal for success metrics
      teal: {
        50: '#f0fdfa',
        100: '#ccfbf1',
        200: '#99f6e4',
        300: '#5eead4',
        400: '#2dd4bf',
        500: '#14b8a6', // Growth indicators
        600: '#0d9488',
        700: '#0f766e',
        800: '#115e59',
        900: '#134e4a',
        950: '#042f2e',
      },
      // Semantic colors for marketing
      success: {
        light: '#dcfce7',
        DEFAULT: '#22c55e',
        dark: '#16a34a',
      },
      warning: {
        light: '#fef3c7',
        DEFAULT: '#f59e0b',
        dark: '#d97706',
      },
      error: {
        light: '#fee2e2',
        DEFAULT: '#ef4444',
        dark: '#dc2626',
      },
    },
  },

  // Extended spacing for marketing sections
  spacing: {
    '18': '4.5rem',   // 72px
    '22': '5.5rem',   // 88px
    '26': '6.5rem',   // 104px
    '30': '7.5rem',   // 120px
    '34': '8.5rem',   // 136px
    '38': '9.5rem',   // 152px
    '42': '10.5rem',  // 168px
    '46': '11.5rem',  // 184px
    '50': '12.5rem',  // 200px
    '54': '13.5rem',  // 216px
    '58': '14.5rem',  // 232px
    '62': '15.5rem',  // 248px
    '66': '16.5rem',  // 264px
    '70': '17.5rem',  // 280px
    '74': '18.5rem',  // 296px
    '78': '19.5rem',  // 312px
    '82': '20.5rem',  // 328px
    '86': '21.5rem',  // 344px
    '90': '22.5rem',  // 360px
    '94': '23.5rem',  // 376px
    '98': '24.5rem',  // 392px
  },

  // Typography extensions
  fontSize: {
    // Marketing hero sizes
    'hero-xs': ['2.5rem', { lineHeight: '1', letterSpacing: '-0.03em' }],
    'hero-sm': ['3rem', { lineHeight: '1', letterSpacing: '-0.03em' }],
    'hero-md': ['3.75rem', { lineHeight: '1', letterSpacing: '-0.03em' }],
    'hero-lg': ['4.5rem', { lineHeight: '0.95', letterSpacing: '-0.03em' }],
    'hero-xl': ['5rem', { lineHeight: '0.95', letterSpacing: '-0.04em' }],
    'hero-2xl': ['6rem', { lineHeight: '0.9', letterSpacing: '-0.04em' }],

    // Marketing body sizes
    'marketing-xs': ['0.75rem', { lineHeight: '1rem' }],
    'marketing-sm': ['0.875rem', { lineHeight: '1.25rem' }],
    'marketing-base': ['1rem', { lineHeight: '1.75rem' }],
    'marketing-lg': ['1.125rem', { lineHeight: '1.875rem' }],
    'marketing-xl': ['1.25rem', { lineHeight: '2rem' }],
  },

  // Font weight extensions
  fontWeight: {
    'hairline': '100',
    'thin': '200',
    'light': '300',
    'normal': '400',
    'medium': '500',
    'semibold': '600',
    'bold': '700',
    'extrabold': '800',
    'black': '900',
  },

  // Background gradients for marketing
  backgroundImage: {
    // Hero gradients
    'hero-primary': 'linear-gradient(135deg, #3b82f6 0%, #1e40af 100%)',
    'hero-aurora': 'linear-gradient(135deg, #3b82f6 0%, #a855f7 50%, #14b8a6 100%)',
    'hero-sunset': 'linear-gradient(135deg, #f59e0b 0%, #dc2626 100%)',
    'hero-mesh': `
      radial-gradient(circle at 20% 50%, rgba(120, 119, 198, 0.3) 0%, transparent 50%),
      radial-gradient(circle at 80% 80%, rgba(255, 119, 198, 0.3) 0%, transparent 50%),
      radial-gradient(circle at 40% 20%, rgba(255, 219, 120, 0.3) 0%, transparent 50%)
    `,

    // Feature gradients
    'ai-glow': 'radial-gradient(circle, rgba(168, 85, 247, 0.2) 0%, transparent 70%)',
    'card-hover': 'linear-gradient(135deg, rgba(37, 99, 235, 0.05) 0%, rgba(147, 51, 234, 0.05) 100%)',

    // Text gradients
    'text-premium': 'linear-gradient(135deg, #3b82f6 0%, #a855f7 100%)',
    'text-gold': 'linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%)',
    'text-success': 'linear-gradient(135deg, #14b8a6 0%, #22c55e 100%)',
  },

  // Box shadows for marketing
  boxShadow: {
    // Elevation shadows
    'marketing-xs': '0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24)',
    'marketing-sm': '0 3px 6px rgba(0, 0, 0, 0.15), 0 2px 4px rgba(0, 0, 0, 0.12)',
    'marketing-md': '0 10px 20px rgba(0, 0, 0, 0.15), 0 3px 6px rgba(0, 0, 0, 0.10)',
    'marketing-lg': '0 15px 25px rgba(0, 0, 0, 0.15), 0 5px 10px rgba(0, 0, 0, 0.05)',
    'marketing-xl': '0 20px 40px rgba(0, 0, 0, 0.20), 0 10px 20px rgba(0, 0, 0, 0.10)',

    // Colored shadows
    'primary': '0 10px 40px rgba(37, 99, 235, 0.3)',
    'accent': '0 10px 40px rgba(147, 51, 234, 0.3)',
    'success': '0 10px 40px rgba(34, 197, 94, 0.3)',
    'warning': '0 10px 40px rgba(245, 158, 11, 0.3)',
    'error': '0 10px 40px rgba(239, 68, 68, 0.3)',

    // Glow effects
    'glow-primary': '0 0 30px rgba(37, 99, 235, 0.5)',
    'glow-accent': '0 0 30px rgba(147, 51, 234, 0.5)',
    'glow-success': '0 0 30px rgba(34, 197, 94, 0.5)',
  },

  // Animation extensions
  animation: {
    // Fade animations
    'fade-in': 'fadeIn 0.5s ease-in-out',
    'fade-in-up': 'fadeInUp 0.5s ease-out',
    'fade-in-down': 'fadeInDown 0.5s ease-out',

    // Slide animations
    'slide-in-right': 'slideInRight 0.3s ease-out',
    'slide-in-left': 'slideInLeft 0.3s ease-out',

    // Scale animations
    'scale-in': 'scaleIn 0.3s ease-out',
    'scale-out': 'scaleOut 0.3s ease-in',

    // Special effects
    'gradient-shift': 'gradientShift 3s ease infinite',
    'glow-pulse': 'glowPulse 2s ease-in-out infinite',
    'float': 'float 3s ease-in-out infinite',
    'shimmer': 'shimmer 2s linear infinite',
  },

  keyframes: {
    fadeIn: {
      '0%': { opacity: '0' },
      '100%': { opacity: '1' },
    },
    fadeInUp: {
      '0%': {
        opacity: '0',
        transform: 'translateY(30px)',
      },
      '100%': {
        opacity: '1',
        transform: 'translateY(0)',
      },
    },
    fadeInDown: {
      '0%': {
        opacity: '0',
        transform: 'translateY(-30px)',
      },
      '100%': {
        opacity: '1',
        transform: 'translateY(0)',
      },
    },
    slideInRight: {
      '0%': { transform: 'translateX(100%)' },
      '100%': { transform: 'translateX(0)' },
    },
    slideInLeft: {
      '0%': { transform: 'translateX(-100%)' },
      '100%': { transform: 'translateX(0)' },
    },
    scaleIn: {
      '0%': {
        opacity: '0',
        transform: 'scale(0.9)',
      },
      '100%': {
        opacity: '1',
        transform: 'scale(1)',
      },
    },
    scaleOut: {
      '0%': {
        opacity: '1',
        transform: 'scale(1)',
      },
      '100%': {
        opacity: '0',
        transform: 'scale(0.9)',
      },
    },
    gradientShift: {
      '0%, 100%': { backgroundPosition: '0% 50%' },
      '50%': { backgroundPosition: '100% 50%' },
    },
    glowPulse: {
      '0%, 100%': {
        boxShadow: '0 0 20px rgba(59, 130, 246, 0.5)',
      },
      '50%': {
        boxShadow: '0 0 40px rgba(59, 130, 246, 0.8)',
      },
    },
    float: {
      '0%, 100%': { transform: 'translateY(0)' },
      '50%': { transform: 'translateY(-10px)' },
    },
    shimmer: {
      '0%': { backgroundPosition: '-1000px 0' },
      '100%': { backgroundPosition: '1000px 0' },
    },
  },

  // Transition timing functions
  transitionTimingFunction: {
    'smooth': 'cubic-bezier(0.37, 0, 0.63, 1)',
    'energetic': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
    'dramatic': 'cubic-bezier(0.22, 1, 0.36, 1)',
    'out-expo': 'cubic-bezier(0.19, 1, 0.22, 1)',
    'out-back': 'cubic-bezier(0.175, 0.885, 0.32, 1.275)',
  },

  // Border radius extensions
  borderRadius: {
    'marketing-sm': '0.375rem',  // 6px
    'marketing-md': '0.5rem',    // 8px
    'marketing-lg': '0.75rem',   // 12px
    'marketing-xl': '1rem',      // 16px
    'marketing-2xl': '1.5rem',   // 24px
    'marketing-3xl': '2rem',     // 32px
  },

  // Z-index for marketing components
  zIndex: {
    'dropdown': '1000',
    'sticky': '1020',
    'fixed': '1030',
    'modal-backdrop': '1040',
    'modal': '1050',
    'popover': '1060',
    'tooltip': '1070',
    'notification': '1080',
    'marketing-hero': '100',
    'marketing-nav': '1000',
    'marketing-cta': '200',
  },

  // Backdrop filters
  backdropBlur: {
    'marketing-xs': '2px',
    'marketing-sm': '8px',
    'marketing-md': '12px',
    'marketing-lg': '16px',
    'marketing-xl': '24px',
  },

  // Screen breakpoints (if different from defaults)
  screens: {
    'xs': '475px',
    'sm': '640px',
    'md': '768px',
    'lg': '1024px',
    'xl': '1280px',
    '2xl': '1536px',
    '3xl': '1920px',
    '4xl': '2560px',
  },
};

/**
 * Usage in tailwind.config.ts:
 *
 * import { marketingThemeExtensions } from './marketing-theme';
 *
 * export default {
 *   // ... existing config
 *   theme: {
 *     extend: {
 *       ...marketingThemeExtensions,
 *       // ... other extensions
 *     }
 *   }
 * }
 */

// Utility classes for marketing components
export const marketingUtilities = {
  '.text-gradient-premium': {
    background: 'linear-gradient(135deg, #3b82f6 0%, #a855f7 100%)',
    '-webkit-background-clip': 'text',
    '-webkit-text-fill-color': 'transparent',
    'background-clip': 'text',
  },
  '.text-gradient-gold': {
    background: 'linear-gradient(135deg, #f59e0b 0%, #fbbf24 100%)',
    '-webkit-background-clip': 'text',
    '-webkit-text-fill-color': 'transparent',
    'background-clip': 'text',
  },
  '.glass-card': {
    background: 'rgba(255, 255, 255, 0.7)',
    'backdrop-filter': 'blur(10px)',
    '-webkit-backdrop-filter': 'blur(10px)',
    border: '1px solid rgba(255, 255, 255, 0.2)',
  },
  '.glass-dark': {
    background: 'rgba(0, 0, 0, 0.5)',
    'backdrop-filter': 'blur(10px)',
    '-webkit-backdrop-filter': 'blur(10px)',
    border: '1px solid rgba(255, 255, 255, 0.1)',
  },
  '.hover-lift': {
    transition: 'transform 250ms cubic-bezier(0.19, 1, 0.22, 1), box-shadow 250ms cubic-bezier(0.19, 1, 0.22, 1)',
    '&:hover': {
      transform: 'translateY(-4px)',
      boxShadow: '0 20px 40px rgba(0, 0, 0, 0.15)',
    },
  },
  '.hover-glow': {
    transition: 'box-shadow 250ms ease',
    '&:hover': {
      boxShadow: '0 0 30px rgba(59, 130, 246, 0.4)',
    },
  },
  '.marketing-container': {
    width: '100%',
    marginLeft: 'auto',
    marginRight: 'auto',
    paddingLeft: '1rem',
    paddingRight: '1rem',
    '@screen sm': {
      maxWidth: '640px',
      paddingLeft: '1.5rem',
      paddingRight: '1.5rem',
    },
    '@screen md': {
      maxWidth: '768px',
    },
    '@screen lg': {
      maxWidth: '1024px',
      paddingLeft: '2rem',
      paddingRight: '2rem',
    },
    '@screen xl': {
      maxWidth: '1280px',
    },
    '@screen 2xl': {
      maxWidth: '1536px',
    },
  },
  '.marketing-section': {
    paddingTop: '4rem',
    paddingBottom: '4rem',
    '@screen md': {
      paddingTop: '6rem',
      paddingBottom: '6rem',
    },
    '@screen lg': {
      paddingTop: '8rem',
      paddingBottom: '8rem',
    },
  },
};