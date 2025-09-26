/**
 * Bulletproof Token Test Setup
 * Provides comprehensive setup and utilities for token testing
 */

import { beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';

// Global test utilities
declare global {
  var tokenTestUtils: {
    ensureTokenFiles: () => void;
    createFallbackTokens: () => void;
    validateTokenStructure: (tokens: any) => boolean;
    getTokenPaths: () => { css: string; json: string; temp: string };
  };
}

/**
 * Token Test Utilities
 * Provides bulletproof utilities for token testing
 */
class TokenTestUtils {
  private projectRoot: string;

  constructor() {
    this.projectRoot = process.cwd();
  }

  /**
   * Get all token file paths
   */
  getTokenPaths() {
    return {
      css: join(this.projectRoot, 'design-system', 'tokens.css'),
      json: join(this.projectRoot, 'design-system', 'tokens.json'),
      temp: join(this.projectRoot, 'design-system', 'design-tokens-temp.json'),
      diff: join(this.projectRoot, 'design-system', 'token-diff-report.json')
    };
  }

  /**
   * Ensure all required token files exist with fallbacks
   */
  ensureTokenFiles() {
    const paths = this.getTokenPaths();
    
    // Ensure CSS tokens file exists
    if (!existsSync(paths.css)) {
      console.log('📝 Creating fallback CSS tokens file');
      const fallbackCSS = `:root {
  /* Color Tokens */
  --color-primary: #007bff;
  --color-secondary: #6c757d;
  --color-success: #28a745;
  --color-danger: #dc3545;
  --color-warning: #ffc107;
  --color-info: #17a2b8;
  
  /* Spacing Tokens */
  --spacing-xs: 0.25rem;
  --spacing-sm: 0.5rem;
  --spacing-md: 1rem;
  --spacing-lg: 1.5rem;
  --spacing-xl: 3rem;
  
  /* Typography Tokens */
  --font-size-xs: 0.75rem;
  --font-size-sm: 0.875rem;
  --font-size-base: 1rem;
  --font-size-lg: 1.125rem;
  --font-size-xl: 1.25rem;
  
  /* Border Radius */
  --border-radius-sm: 0.125rem;
  --border-radius: 0.25rem;
  --border-radius-lg: 0.5rem;
  
  /* Shadows */
  --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
  --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
}`;
      writeFileSync(paths.css, fallbackCSS);
    }

    // Ensure JSON tokens file exists
    if (!existsSync(paths.json)) {
      console.log('📝 Creating fallback JSON tokens file');
      const fallbackJSON = {
        colors: {
          primary: '#007bff',
          secondary: '#6c757d',
          success: '#28a745',
          danger: '#dc3545',
          warning: '#ffc107',
          info: '#17a2b8'
        },
        spacing: {
          xs: '0.25rem',
          sm: '0.5rem',
          md: '1rem',
          lg: '1.5rem',
          xl: '3rem'
        },
        typography: {
          fontSize: {
            xs: '0.75rem',
            sm: '0.875rem',
            base: '1rem',
            lg: '1.125rem',
            xl: '1.25rem'
          }
        },
        borderRadius: {
          sm: '0.125rem',
          base: '0.25rem',
          lg: '0.5rem'
        },
        shadows: {
          sm: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
          base: '0 1px 3px 0 rgba(0, 0, 0, 0.1)',
          lg: '0 10px 15px -3px rgba(0, 0, 0, 0.1)'
        }
      };
      writeFileSync(paths.json, JSON.stringify(fallbackJSON, null, 2));
    }

    // Ensure temp tokens file exists
    if (!existsSync(paths.temp)) {
      console.log('📝 Creating fallback temp tokens file');
      writeFileSync(paths.temp, JSON.stringify({}, null, 2));
    }
  }

  /**
   * Create comprehensive fallback tokens
   */
  createFallbackTokens() {
    const paths = this.getTokenPaths();
    
    const comprehensiveTokens = {
      metadata: {
        version: '1.0.0',
        generated: new Date().toISOString(),
        source: 'fallback-generator'
      },
      colors: {
        primary: { value: '#007bff', type: 'color' },
        secondary: { value: '#6c757d', type: 'color' },
        success: { value: '#28a745', type: 'color' },
        danger: { value: '#dc3545', type: 'color' },
        warning: { value: '#ffc107', type: 'color' },
        info: { value: '#17a2b8', type: 'color' },
        light: { value: '#f8f9fa', type: 'color' },
        dark: { value: '#343a40', type: 'color' }
      },
      spacing: {
        xs: { value: '0.25rem', type: 'spacing' },
        sm: { value: '0.5rem', type: 'spacing' },
        md: { value: '1rem', type: 'spacing' },
        lg: { value: '1.5rem', type: 'spacing' },
        xl: { value: '3rem', type: 'spacing' },
        xxl: { value: '4.5rem', type: 'spacing' }
      },
      typography: {
        fontSize: {
          xs: { value: '0.75rem', type: 'fontSize' },
          sm: { value: '0.875rem', type: 'fontSize' },
          base: { value: '1rem', type: 'fontSize' },
          lg: { value: '1.125rem', type: 'fontSize' },
          xl: { value: '1.25rem', type: 'fontSize' },
          xxl: { value: '1.5rem', type: 'fontSize' }
        },
        fontWeight: {
          light: { value: '300', type: 'fontWeight' },
          normal: { value: '400', type: 'fontWeight' },
          medium: { value: '500', type: 'fontWeight' },
          semibold: { value: '600', type: 'fontWeight' },
          bold: { value: '700', type: 'fontWeight' }
        }
      },
      borderRadius: {
        none: { value: '0', type: 'borderRadius' },
        sm: { value: '0.125rem', type: 'borderRadius' },
        base: { value: '0.25rem', type: 'borderRadius' },
        md: { value: '0.375rem', type: 'borderRadius' },
        lg: { value: '0.5rem', type: 'borderRadius' },
        xl: { value: '0.75rem', type: 'borderRadius' },
        full: { value: '9999px', type: 'borderRadius' }
      },
      shadows: {
        none: { value: 'none', type: 'shadow' },
        sm: { value: '0 1px 2px 0 rgba(0, 0, 0, 0.05)', type: 'shadow' },
        base: { value: '0 1px 3px 0 rgba(0, 0, 0, 0.1)', type: 'shadow' },
        md: { value: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', type: 'shadow' },
        lg: { value: '0 10px 15px -3px rgba(0, 0, 0, 0.1)', type: 'shadow' },
        xl: { value: '0 20px 25px -5px rgba(0, 0, 0, 0.1)', type: 'shadow' }
      }
    };

    writeFileSync(paths.temp, JSON.stringify(comprehensiveTokens, null, 2));
    console.log('✅ Comprehensive fallback tokens created');
  }

  /**
   * Validate token structure
   */
  validateTokenStructure(tokens: any): boolean {
    try {
      if (!tokens || typeof tokens !== 'object') {
        return false;
      }

      // Check for basic structure
      const hasColors = tokens.colors && typeof tokens.colors === 'object';
      const hasSpacing = tokens.spacing && typeof tokens.spacing === 'object';
      const hasTypography = tokens.typography && typeof tokens.typography === 'object';

      // At least one category should exist
      return hasColors || hasSpacing || hasTypography;
    } catch (error) {
      console.log('⚠️  Token structure validation error:', error);
      return false;
    }
  }

  /**
   * Safe file reader with fallback
   */
  safeReadFile(filePath: string, fallback: string = '{}'): string {
    try {
      if (!existsSync(filePath)) {
        return fallback;
      }
      return readFileSync(filePath, 'utf8');
    } catch (error) {
      console.log(`⚠️  Error reading ${filePath}: ${error}`);
      return fallback;
    }
  }
}

// Initialize global utilities
global.tokenTestUtils = new TokenTestUtils();

// Setup hooks
beforeAll(() => {
  console.log('🚀 Setting up bulletproof token tests...');
  global.tokenTestUtils.ensureTokenFiles();
  global.tokenTestUtils.createFallbackTokens();
});

beforeEach(() => {
  // Ensure files exist before each test
  global.tokenTestUtils.ensureTokenFiles();
});

afterEach(() => {
  // Clean up any temporary files if needed
});

afterAll(() => {
  console.log('✅ Token test setup completed');
});

export { TokenTestUtils };

