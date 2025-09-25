/**
 * TAILWIND CONFIGURATION
 * Design system tokens as utility classes
 */

module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx}',
    './components/**/*.{js,ts,jsx,tsx}',
    './design-system/**/*.{js,ts,jsx,tsx}',
  ],
  darkMode: 'class',
  theme: {
    // Override defaults completely for consistency
    colors: {
      transparent: 'transparent',
      current: 'currentColor',

      // Base colors
      black: '#000000',
      white: '#FFFFFF',

      // Gray scale using opacity
      gray: {
        4: 'rgba(0, 0, 0, 0.04)',
        8: 'rgba(0, 0, 0, 0.08)',
        16: 'rgba(0, 0, 0, 0.16)',
        24: 'rgba(0, 0, 0, 0.24)',
        36: 'rgba(0, 0, 0, 0.36)',
        64: 'rgba(0, 0, 0, 0.64)',
        76: 'rgba(0, 0, 0, 0.76)',
      },

      // Accent colors
      blue: {
        500: '#0066FF',
        600: '#0052CC',
        700: '#0047B3',
        50: 'rgba(0, 102, 255, 0.05)',
        100: 'rgba(0, 102, 255, 0.1)',
      },

      // Semantic colors
      green: {
        500: '#00C851',
        600: '#00A041',
        100: 'rgba(0, 200, 81, 0.1)',
      },
      amber: {
        500: '#FFBB33',
        600: '#FF9900',
        100: 'rgba(255, 187, 51, 0.1)',
      },
      red: {
        500: '#FF3547',
        600: '#CC0000',
        100: 'rgba(255, 53, 71, 0.1)',
      },
    },

    spacing: {
      0: '0px',
      px: '1px',
      0.5: '2px',
      1: '4px',     // Base unit
      2: '8px',
      3: '12px',
      4: '16px',
      5: '20px',
      6: '24px',
      8: '32px',
      10: '40px',
      12: '48px',
      13: '52px',
      16: '64px',
      20: '80px',
      21: '84px',
      24: '96px',
      32: '128px',
      40: '160px',
      48: '192px',
      56: '224px',
      64: '256px',
    },

    fontSize: {
      '2xs': ['11px', { lineHeight: '1.5' }],
      xs: ['13px', { lineHeight: '1.5' }],
      sm: ['14px', { lineHeight: '1.5' }],
      base: ['16px', { lineHeight: '1.5' }],
      md: ['20px', { lineHeight: '1.4' }],
      lg: ['28px', { lineHeight: '1.3' }],
      xl: ['40px', { lineHeight: '1.2' }],
      '2xl': ['64px', { lineHeight: '1.1' }],
    },

    fontWeight: {
      normal: '400',
      medium: '500',
    },

    fontFamily: {
      sans: ['-apple-system', 'BlinkMacSystemFont', 'SF Pro Display', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'sans-serif'],
      mono: ['SF Mono', 'Monaco', 'Inconsolata', 'Courier New', 'monospace'],
    },

    borderRadius: {
      none: '0px',
      sm: '2px',
      DEFAULT: '4px',
      full: '9999px',
    },

    borderWidth: {
      DEFAULT: '1px',
      0: '0px',
      2: '2px',
    },

    extend: {
      transitionTimingFunction: {
        'standard': 'cubic-bezier(0.4, 0, 0.2, 1)',
        'accelerate': 'cubic-bezier(0.4, 0, 1, 1)',
        'decelerate': 'cubic-bezier(0, 0, 0.2, 1)',
        'bounce': 'cubic-bezier(0.68, -0.55, 0.265, 1.55)',
      },

      transitionDuration: {
        '0': '0ms',
        '100': '100ms',
        '200': '200ms',
        '300': '300ms',
        '400': '400ms',
        '600': '600ms',
      },

      animation: {
        'spin-slow': 'spin 2s linear infinite',
        'pulse-subtle': 'pulse 3s ease-in-out infinite',
        'bounce-subtle': 'bounce 2s ease-in-out infinite',
        'shimmer': 'shimmer 2s linear infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'fade-out': 'fadeOut 0.3s ease-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'slide-out': 'slideOut 0.3s ease-out',
        'scale-in': 'scaleIn 0.2s ease-out',
        'scale-out': 'scaleOut 0.2s ease-out',
      },

      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '100% 0' },
          '100%': { backgroundPosition: '-100% 0' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        fadeOut: {
          '0%': { opacity: '1' },
          '100%': { opacity: '0' },
        },
        slideIn: {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideOut: {
          '0%': { transform: 'translateY(0)', opacity: '1' },
          '100%': { transform: 'translateY(-20px)', opacity: '0' },
        },
        scaleIn: {
          '0%': { transform: 'scale(0.9)', opacity: '0' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
        scaleOut: {
          '0%': { transform: 'scale(1)', opacity: '1' },
          '100%': { transform: 'scale(0.9)', opacity: '0' },
        },
      },

      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
      },

      screens: {
        'xs': '475px',
        '3xl': '1920px',
      },

      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },

      // Custom utilities
      boxShadow: {
        'subtle': '0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24)',
        'medium': '0 3px 6px rgba(0,0,0,0.15), 0 2px 4px rgba(0,0,0,0.12)',
        'large': '0 10px 20px rgba(0,0,0,0.15), 0 3px 6px rgba(0,0,0,0.10)',
        'xlarge': '0 15px 25px rgba(0,0,0,0.15), 0 5px 10px rgba(0,0,0,0.05)',
        'inner-subtle': 'inset 0 1px 2px rgba(0,0,0,0.05)',
      },

      // Container queries support
      container: {
        center: true,
        padding: {
          DEFAULT: '1rem',
          sm: '2rem',
          lg: '4rem',
          xl: '5rem',
          '2xl': '6rem',
        },
      },
    },
  },

  plugins: [
    // Custom plugin for design system utilities
    function({ addUtilities, addComponents, theme }) {
      // Text rendering utilities
      addUtilities({
        '.text-render-optimize': {
          '-webkit-font-smoothing': 'antialiased',
          '-moz-osx-font-smoothing': 'grayscale',
          'text-rendering': 'optimizeLegibility',
        },
        '.text-render-auto': {
          '-webkit-font-smoothing': 'auto',
          '-moz-osx-font-smoothing': 'auto',
          'text-rendering': 'auto',
        },
      });

      // Performance utilities
      addUtilities({
        '.gpu-accelerated': {
          'transform': 'translateZ(0)',
          'will-change': 'transform',
        },
        '.no-scrollbar': {
          '-ms-overflow-style': 'none',
          'scrollbar-width': 'none',
          '&::-webkit-scrollbar': {
            'display': 'none',
          },
        },
        '.scrollbar-thin': {
          'scrollbar-width': 'thin',
          '&::-webkit-scrollbar': {
            'width': '4px',
            'height': '4px',
          },
        },
      });

      // Safe area utilities for mobile
      addUtilities({
        '.pb-safe': {
          paddingBottom: 'env(safe-area-inset-bottom)',
        },
        '.pt-safe': {
          paddingTop: 'env(safe-area-inset-top)',
        },
        '.pl-safe': {
          paddingLeft: 'env(safe-area-inset-left)',
        },
        '.pr-safe': {
          paddingRight: 'env(safe-area-inset-right)',
        },
      });

      // Component defaults
      addComponents({
        '.btn': {
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '16px 32px',
          fontSize: '16px',
          fontWeight: '500',
          lineHeight: '1',
          borderRadius: '0',
          transitionProperty: 'all',
          transitionDuration: '200ms',
          transitionTimingFunction: 'cubic-bezier(0.4, 0, 0.2, 1)',
          '&:hover': {
            transform: 'scale(1.02)',
          },
          '&:active': {
            transform: 'scale(0.98)',
          },
        },
        '.card': {
          backgroundColor: theme('colors.white'),
          border: '1px solid',
          borderColor: theme('colors.gray.8'),
          padding: theme('spacing.5'),
          '.dark &': {
            backgroundColor: theme('colors.black'),
            borderColor: 'rgba(255, 255, 255, 0.08)',
          },
        },
        '.input': {
          width: '100%',
          height: '48px',
          padding: '12px 16px',
          backgroundColor: 'transparent',
          border: '1px solid',
          borderColor: theme('colors.gray.8'),
          fontSize: '16px',
          transitionProperty: 'all',
          transitionDuration: '200ms',
          '&:focus': {
            outline: 'none',
            borderColor: theme('colors.gray.24'),
          },
          '.dark &': {
            borderColor: 'rgba(255, 255, 255, 0.08)',
            '&:focus': {
              borderColor: 'rgba(255, 255, 255, 0.24)',
            },
          },
        },
      });
    },

    // Container queries plugin
    require('@tailwindcss/container-queries'),
  ],
};