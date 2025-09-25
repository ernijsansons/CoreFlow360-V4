/**
 * CoreFlow360 V4 Tailwind Tokens Extension
 * Maps design tokens to Tailwind CSS theme configuration
 * Usage: Import and extend your tailwind.config.js with this configuration
 */

const plugin = require('tailwindcss/plugin');

/**
 * Design Token to Tailwind Theme Mapping
 * Converts CSS custom properties to Tailwind theme values
 */
const tokenTheme = {
  colors: {
    // Semantic Colors (using CSS variables)
    'canvas': 'var(--bg-canvas)',
    'surface': 'var(--bg-surface)',
    'muted': 'var(--bg-muted)',
    
    // Text Colors
    'primary': 'var(--text-primary)',
    'secondary': 'var(--text-secondary)',
    'muted-foreground': 'var(--text-muted)',
    'inverse': 'var(--text-inverse)',
    
    // Border Colors
    'border': 'var(--border-default)',
    'border-muted': 'var(--border-muted)',
    'border-strong': 'var(--border-strong)',
    
    // Accent Colors
    'accent': {
      DEFAULT: 'var(--accent-primary)',
      hover: 'var(--accent-primary-hover)',
      muted: 'var(--accent-primary-muted)',
    },
    
    // State Colors
    'success': {
      DEFAULT: 'var(--state-success)',
      muted: 'var(--state-success-muted)',
    },
    'warning': {
      DEFAULT: 'var(--state-warning)',
      muted: 'var(--state-warning-muted)',
    },
    'error': {
      DEFAULT: 'var(--state-error)',
      muted: 'var(--state-error-muted)',
    },
    'destructive': {
      DEFAULT: 'var(--state-error)',
      muted: 'var(--state-error-muted)',
    },
    'info': {
      DEFAULT: 'var(--state-info)',
      muted: 'var(--state-info-muted)',
    },
    
    // Raw Colors (for advanced usage)
    white: 'var(--color-white)',
    black: 'var(--color-black)',
    gray: {
      50: 'var(--color-gray-50)',
      100: 'var(--color-gray-100)',
      200: 'var(--color-gray-200)',
      300: 'var(--color-gray-300)',
      400: 'var(--color-gray-400)',
      500: 'var(--color-gray-500)',
      600: 'var(--color-gray-600)',
      700: 'var(--color-gray-700)',
      800: 'var(--color-gray-800)',
      900: 'var(--color-gray-900)',
    },
    blue: {
      50: 'var(--color-blue-50)',
      100: 'var(--color-blue-100)',
      200: 'var(--color-blue-200)',
      300: 'var(--color-blue-300)',
      400: 'var(--color-blue-400)',
      500: 'var(--color-blue-500)',
      600: 'var(--color-blue-600)',
      700: 'var(--color-blue-700)',
      800: 'var(--color-blue-800)',
      900: 'var(--color-blue-900)',
    },
    green: {
      50: 'var(--color-green-50)',
      100: 'var(--color-green-100)',
      200: 'var(--color-green-200)',
      300: 'var(--color-green-300)',
      400: 'var(--color-green-400)',
      500: 'var(--color-green-500)',
      600: 'var(--color-green-600)',
      700: 'var(--color-green-700)',
      800: 'var(--color-green-800)',
      900: 'var(--color-green-900)',
    },
    red: {
      50: 'var(--color-red-50)',
      100: 'var(--color-red-100)',
      200: 'var(--color-red-200)',
      300: 'var(--color-red-300)',
      400: 'var(--color-red-400)',
      500: 'var(--color-red-500)',
      600: 'var(--color-red-600)',
      700: 'var(--color-red-700)',
      800: 'var(--color-red-800)',
      900: 'var(--color-red-900)',
    },
    yellow: {
      50: 'var(--color-yellow-50)',
      100: 'var(--color-yellow-100)',
      200: 'var(--color-yellow-200)',
      300: 'var(--color-yellow-300)',
      400: 'var(--color-yellow-400)',
      500: 'var(--color-yellow-500)',
      600: 'var(--color-yellow-600)',
      700: 'var(--color-yellow-700)',
      800: 'var(--color-yellow-800)',
      900: 'var(--color-yellow-900)',
    },
    purple: {
      50: 'var(--color-purple-50)',
      100: 'var(--color-purple-100)',
      200: 'var(--color-purple-200)',
      300: 'var(--color-purple-300)',
      400: 'var(--color-purple-400)',
      500: 'var(--color-purple-500)',
      600: 'var(--color-purple-600)',
      700: 'var(--color-purple-700)',
      800: 'var(--color-purple-800)',
      900: 'var(--color-purple-900)',
    },
  },
  
  fontFamily: {
    sans: 'var(--font-family-sans)'.split(', '),
    mono: 'var(--font-family-mono)'.split(', '),
  },
  
  fontSize: {
    xs: 'var(--font-size-xs)',
    sm: 'var(--font-size-sm)',
    base: 'var(--font-size-base)',
    lg: 'var(--font-size-lg)',
    xl: 'var(--font-size-xl)',
    '2xl': 'var(--font-size-2xl)',
    '3xl': 'var(--font-size-3xl)',
    '4xl': 'var(--font-size-4xl)',
    '5xl': 'var(--font-size-5xl)',
    '6xl': 'var(--font-size-6xl)',
  },
  
  fontWeight: {
    thin: 'var(--font-weight-thin)',
    extralight: 'var(--font-weight-extralight)',
    light: 'var(--font-weight-light)',
    normal: 'var(--font-weight-normal)',
    medium: 'var(--font-weight-medium)',
    semibold: 'var(--font-weight-semibold)',
    bold: 'var(--font-weight-bold)',
    extrabold: 'var(--font-weight-extrabold)',
    black: 'var(--font-weight-black)',
  },
  
  lineHeight: {
    tight: 'var(--line-height-tight)',
    snug: 'var(--line-height-snug)',
    normal: 'var(--line-height-normal)',
    relaxed: 'var(--line-height-relaxed)',
    loose: 'var(--line-height-loose)',
  },
  
  letterSpacing: {
    tighter: 'var(--letter-spacing-tighter)',
    tight: 'var(--letter-spacing-tight)',
    normal: 'var(--letter-spacing-normal)',
    wide: 'var(--letter-spacing-wide)',
    wider: 'var(--letter-spacing-wider)',
    widest: 'var(--letter-spacing-widest)',
  },
  
  spacing: {
    0: 'var(--spacing-0)',
    1: 'var(--spacing-1)',
    2: 'var(--spacing-2)',
    3: 'var(--spacing-3)',
    4: 'var(--spacing-4)',
    5: 'var(--spacing-5)',
    6: 'var(--spacing-6)',
    8: 'var(--spacing-8)',
    10: 'var(--spacing-10)',
    12: 'var(--spacing-12)',
    16: 'var(--spacing-16)',
    20: 'var(--spacing-20)',
    24: 'var(--spacing-24)',
    32: 'var(--spacing-32)',
    
    // Semantic Spacing
    'component-xs': 'var(--spacing-component-xs)',
    'component-sm': 'var(--spacing-component-sm)',
    'component-md': 'var(--spacing-component-md)',
    'component-lg': 'var(--spacing-component-lg)',
    'component-xl': 'var(--spacing-component-xl)',
    
    'layout-xs': 'var(--spacing-layout-xs)',
    'layout-sm': 'var(--spacing-layout-sm)',
    'layout-md': 'var(--spacing-layout-md)',
    'layout-lg': 'var(--spacing-layout-lg)',
    'layout-xl': 'var(--spacing-layout-xl)',
  },
  
  borderRadius: {
    none: 'var(--radius-none)',
    sm: 'var(--radius-sm)',
    DEFAULT: 'var(--radius-base)',
    md: 'var(--radius-md)',
    lg: 'var(--radius-lg)',
    xl: 'var(--radius-xl)',
    '2xl': 'var(--radius-2xl)',
    '3xl': 'var(--radius-3xl)',
    full: 'var(--radius-full)',
    
    // Component-specific
    button: 'var(--radius-button)',
    card: 'var(--radius-card)',
    input: 'var(--radius-input)',
    modal: 'var(--radius-modal)',
  },
  
  boxShadow: {
    none: 'var(--shadow-none)',
    sm: 'var(--shadow-sm)',
    DEFAULT: 'var(--shadow-base)',
    md: 'var(--shadow-md)',
    lg: 'var(--shadow-lg)',
    xl: 'var(--shadow-xl)',
    '2xl': 'var(--shadow-2xl)',
    
    // Component-specific
    button: 'var(--shadow-button)',
    card: 'var(--shadow-card)',
    modal: 'var(--shadow-modal)',
    dropdown: 'var(--shadow-dropdown)',
  },
  
  screens: {
    sm: 'var(--breakpoint-sm)',
    md: 'var(--breakpoint-md)',
    lg: 'var(--breakpoint-lg)',
    xl: 'var(--breakpoint-xl)',
    '2xl': 'var(--breakpoint-2xl)',
  },
  
  transitionDuration: {
    instant: 'var(--duration-instant)',
    fast: 'var(--duration-fast)',
    DEFAULT: 'var(--duration-normal)',
    slow: 'var(--duration-slow)',
  },
  
  transitionTimingFunction: {
    linear: 'var(--easing-linear)',
    DEFAULT: 'var(--easing-ease)',
    in: 'var(--easing-ease-in)',
    out: 'var(--easing-ease-out)',
    'in-out': 'var(--easing-ease-in-out)',
  },
};

/**
 * Custom Tailwind Plugin for Design Tokens
 * Adds utility classes for semantic tokens
 */
const designTokensPlugin = plugin(function({ addUtilities, addComponents }) {
  // Background utilities
  addUtilities({
    '.bg-canvas': { 'background-color': 'var(--bg-canvas)' },
    '.bg-surface': { 'background-color': 'var(--bg-surface)' },
    '.bg-muted': { 'background-color': 'var(--bg-muted)' },
  });
  
  // Text utilities
  addUtilities({
    '.text-primary': { color: 'var(--text-primary)' },
    '.text-secondary': { color: 'var(--text-secondary)' },
    '.text-muted-foreground': { color: 'var(--text-muted)' },
    '.text-inverse': { color: 'var(--text-inverse)' },
  });
  
  // Border utilities
  addUtilities({
    '.border-default': { 'border-color': 'var(--border-default)' },
    '.border-muted': { 'border-color': 'var(--border-muted)' },
    '.border-strong': { 'border-color': 'var(--border-strong)' },
  });
  
  // State utilities
  addUtilities({
    '.text-success': { color: 'var(--state-success)' },
    '.text-warning': { color: 'var(--state-warning)' },
    '.text-error': { color: 'var(--state-error)' },
    '.text-destructive': { color: 'var(--state-error)' },
    '.text-info': { color: 'var(--state-info)' },
    
    '.bg-success': { 'background-color': 'var(--state-success-muted)' },
    '.bg-warning': { 'background-color': 'var(--state-warning-muted)' },
    '.bg-error': { 'background-color': 'var(--state-error-muted)' },
    '.bg-destructive': { 'background-color': 'var(--state-error-muted)' },
    '.bg-info': { 'background-color': 'var(--state-info-muted)' },
  });
  
  // Typography components
  addComponents({
    '.heading-1': {
      font: 'var(--typography-heading-1)',
      'letter-spacing': 'var(--letter-spacing-tight)',
    },
    '.heading-2': {
      font: 'var(--typography-heading-2)',
      'letter-spacing': 'var(--letter-spacing-tight)',
    },
    '.heading-3': {
      font: 'var(--typography-heading-3)',
    },
    '.heading-4': {
      font: 'var(--typography-heading-4)',
    },
    '.body-large': {
      font: 'var(--typography-body-large)',
    },
    '.body-base': {
      font: 'var(--typography-body-base)',
    },
    '.body-small': {
      font: 'var(--typography-body-small)',
    },
    '.caption': {
      font: 'var(--typography-caption)',
      'letter-spacing': 'var(--letter-spacing-wide)',
    },
  });
  
  // Focus ring utility
  addUtilities({
    '.focus-ring': {
      outline: '2px solid transparent',
      'outline-offset': '2px',
      '&:focus': {
        outline: '2px solid var(--accent-primary)',
        'outline-offset': '2px',
      },
    },
  });
});

/**
 * Component-specific class mappings
 * Maps common component patterns to semantic tokens
 */
const componentMappings = {
  // Button mappings
  '.btn-primary': {
    'background-color': 'var(--accent-primary)',
    color: 'var(--text-inverse)',
    'border-radius': 'var(--radius-button)',
    'box-shadow': 'var(--shadow-button)',
    '&:hover': {
      'background-color': 'var(--accent-primary-hover)',
    },
  },
  
  '.btn-secondary': {
    'background-color': 'var(--bg-surface)',
    color: 'var(--text-primary)',
    border: '1px solid var(--border-default)',
    'border-radius': 'var(--radius-button)',
    '&:hover': {
      'background-color': 'var(--bg-muted)',
    },
  },
  
  // Card mappings
  '.card': {
    'background-color': 'var(--bg-surface)',
    'border-radius': 'var(--radius-card)',
    'box-shadow': 'var(--shadow-card)',
    border: '1px solid var(--border-muted)',
    padding: 'var(--spacing-component-lg)',
  },
  
  // Input mappings
  '.input': {
    'background-color': 'var(--bg-canvas)',
    color: 'var(--text-primary)',
    border: '1px solid var(--border-default)',
    'border-radius': 'var(--radius-input)',
    padding: 'var(--spacing-component-sm) var(--spacing-component-md)',
    '&:focus': {
      outline: '2px solid var(--accent-primary)',
      'outline-offset': '2px',
      'border-color': 'var(--accent-primary)',
    },
    '&::placeholder': {
      color: 'var(--text-muted)',
    },
  },
};

/**
 * Main export - Tailwind theme extension
 */
module.exports = {
  theme: {
    extend: tokenTheme,
  },
  plugins: [
    designTokensPlugin,
    plugin(function({ addComponents }) {
      addComponents(componentMappings);
    }),
  ],
};

/**
 * Alternative export for manual theme extension
 * Use this if you want to merge with existing config manually
 */
module.exports.tokenTheme = tokenTheme;
module.exports.designTokensPlugin = designTokensPlugin;
module.exports.componentMappings = componentMappings;

/**
 * Usage Examples:
 * 
 * // Option 1: Direct import (recommended)
 * const tokenConfig = require('./tailwind.tokens.cjs');
 * module.exports = {
 *   ...tokenConfig,
 *   content: ['./src/**/*.{js,ts,jsx,tsx}'],
 *   // your other config
 * };
 * 
 * // Option 2: Manual merge
 * const { tokenTheme, designTokensPlugin } = require('./tailwind.tokens.cjs');
 * module.exports = {
 *   theme: {
 *     extend: {
 *       ...tokenTheme,
 *       // your other theme extensions
 *     },
 *   },
 *   plugins: [
 *     designTokensPlugin,
 *     // your other plugins
 *   ],
 *   // your other config
 * };
 */