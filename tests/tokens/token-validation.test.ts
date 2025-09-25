import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Design Token Validation', () => {
  let tokens: any;

  beforeAll(() => {
    const tokenPath = path.join(process.cwd(), 'design-system', 'design-tokens.json');
    const fileContent = fs.readFileSync(tokenPath, 'utf8');
    tokens = JSON.parse(fileContent);
  });

  describe('Token Structure', () => {
    it('should have required top-level categories', () => {
      expect(tokens).toHaveProperty('global');
      expect(tokens).toHaveProperty('semantic');
      expect(tokens).toHaveProperty('$themes');
      expect(tokens).toHaveProperty('dark');
      expect(tokens).toHaveProperty('$metadata');
    });

    it('should have required global categories', () => {
      expect(tokens.global).toHaveProperty('colors');
      expect(tokens.global).toHaveProperty('typography');
      expect(tokens.global).toHaveProperty('spacing');
      expect(tokens.global).toHaveProperty('radius'); // Fixed: was borderRadius
      expect(tokens.global).toHaveProperty('shadows'); // Fixed: was boxShadow
      expect(tokens.global).toHaveProperty('effects'); // Fixed: added missing
    });

    it('should have global color tokens including primary', () => {
      expect(tokens.global.colors).toHaveProperty('white');
      expect(tokens.global.colors).toHaveProperty('black');
      expect(tokens.global.colors).toHaveProperty('gray');
      expect(tokens.global.colors).toHaveProperty('blue');
      expect(tokens.global.colors).toHaveProperty('green');
      expect(tokens.global.colors).toHaveProperty('red');
      expect(tokens.global.colors).toHaveProperty('yellow');
      expect(tokens.global.colors).toHaveProperty('purple');
      expect(tokens.global.colors).toHaveProperty('primary'); // Added by fix script
    });

    it('should have global typography tokens', () => {
      expect(tokens.global.typography).toHaveProperty('fontFamily');
      expect(tokens.global.typography).toHaveProperty('fontSize');
      expect(tokens.global.typography).toHaveProperty('fontWeight');
      expect(tokens.global.typography).toHaveProperty('lineHeight');
      expect(tokens.global.typography).toHaveProperty('letterSpacing');
    });

    it('should have both numeric and semantic spacing keys', () => {
      const spacing = tokens.global.spacing;

      // Numeric keys
      expect(spacing).toHaveProperty('0');
      expect(spacing).toHaveProperty('1');
      expect(spacing).toHaveProperty('2');
      expect(spacing).toHaveProperty('4');

      // Semantic keys (added by fix script)
      expect(spacing).toHaveProperty('xs');
      expect(spacing).toHaveProperty('sm');
      expect(spacing).toHaveProperty('md');
      expect(spacing).toHaveProperty('lg');
      expect(spacing).toHaveProperty('xl');
    });
  });

  describe('Semantic Tokens', () => {
    it('should have semantic color tokens', () => {
      expect(tokens.semantic.colors).toHaveProperty('background');
      expect(tokens.semantic.colors).toHaveProperty('text');
      expect(tokens.semantic.colors).toHaveProperty('border');
      expect(tokens.semantic.colors).toHaveProperty('accent');
      expect(tokens.semantic.colors).toHaveProperty('states');
    });

    it('should have semantic typography tokens', () => {
      expect(tokens.semantic.typography).toHaveProperty('heading');
      expect(tokens.semantic.typography).toHaveProperty('body');
    });

    it('should have semantic spacing tokens', () => {
      expect(tokens.semantic.spacing).toHaveProperty('component');
      expect(tokens.semantic.spacing).toHaveProperty('layout');
    });

    it('should have semantic radii and shadows', () => {
      expect(tokens.semantic).toHaveProperty('radii');
      expect(tokens.semantic).toHaveProperty('shadows');
    });
  });

  describe('Token References', () => {
    function resolveTokenReference(ref: string): any {
      if (!ref.startsWith('{') || !ref.endsWith('}')) {
        return ref;
      }

      const path = ref.slice(1, -1).split('.');
      let current = tokens;

      for (const part of path) {
        if (!current[part]) {
          throw new Error(`Invalid reference: ${ref} (missing: ${part})`);
        }
        current = current[part];
      }

      return current;
    }

    function validateTokenReferences(obj: any, path = ''): string[] {
      const errors: string[] = [];

      for (const [key, value] of Object.entries(obj)) {
        const fullPath = path ? `${path}.${key}` : key;

        if (value && typeof value === 'object') {
          if (value.value !== undefined) {
            // This is a token
            if (typeof value.value === 'string' && value.value.includes('{')) {
              try {
                resolveTokenReference(value.value);
              } catch (error) {
                errors.push(`${fullPath}: ${error.message}`);
              }
            }
          } else if (!key.startsWith('$')) {
            // Continue traversing
            errors.push(...validateTokenReferences(value, fullPath));
          }
        }
      }

      return errors;
    }

    it('should have valid references in all tokens', () => {
      const referenceErrors = validateTokenReferences(tokens);
      expect(referenceErrors).toEqual([]);
    });

    it('should resolve primary color reference correctly', () => {
      const primaryColor = resolveTokenReference(tokens.global.colors.primary.value);
      expect(primaryColor).toHaveProperty('value');
      expect(primaryColor.value).toMatch(/^#[0-9a-fA-F]{6}$/); // Should be a hex color
    });
  });

  describe('Token Types', () => {
    const validTypes = [
      'color',
      'typography',
      'spacing',
      'dimension',
      'shadow',
      'border',
      'opacity',
      'fontFamily',
      'fontSize',
      'fontWeight',
      'lineHeight',
      'letterSpacing',
      'number',
      'duration',
      'cubicBezier',
    ];

    function getAllTokens(obj: any, path = ''): Array<{ path: string; token: any }> {
      const tokens: Array<{ path: string; token: any }> = [];

      for (const [key, value] of Object.entries(obj)) {
        const fullPath = path ? `${path}.${key}` : key;

        if (value && typeof value === 'object') {
          if (value.type !== undefined) {
            // This is a token
            tokens.push({ path: fullPath, token: value });
          } else if (!key.startsWith('$')) {
            // Continue traversing
            tokens.push(...getAllTokens(value, fullPath));
          }
        }
      }

      return tokens;
    }

    it('should have valid token types', () => {
      const allTokens = getAllTokens(tokens);
      const invalidTypes: string[] = [];

      for (const { path, token } of allTokens) {
        if (!validTypes.includes(token.type)) {
          invalidTypes.push(`${path}: ${token.type}`);
        }
      }

      expect(invalidTypes).toEqual([]);
    });
  });

  describe('Theme Support', () => {
    it('should have theme configuration', () => {
      expect(tokens).toHaveProperty('$themes');
      expect(Array.isArray(tokens.$themes)).toBe(true);
      expect(tokens.$themes.length).toBeGreaterThanOrEqual(2);
    });

    it('should have light and dark themes', () => {
      const themeIds = tokens.$themes.map((theme: any) => theme.id);
      expect(themeIds).toContain('light');
      expect(themeIds).toContain('dark');
    });

    it('should have dark theme tokens', () => {
      expect(tokens).toHaveProperty('dark');
      expect(tokens.dark).toHaveProperty('colors');
      expect(tokens.dark.colors).toHaveProperty('background');
      expect(tokens.dark.colors).toHaveProperty('text');
      expect(tokens.dark.colors).toHaveProperty('border');
    });

    it('should have metadata with token set order', () => {
      expect(tokens).toHaveProperty('$metadata');
      expect(tokens.$metadata).toHaveProperty('tokenSetOrder');
      expect(Array.isArray(tokens.$metadata.tokenSetOrder)).toBe(true);
      expect(tokens.$metadata.tokenSetOrder).toContain('global');
      expect(tokens.$metadata.tokenSetOrder).toContain('semantic');
      expect(tokens.$metadata.tokenSetOrder).toContain('dark');
    });
  });

  describe('8px Grid System', () => {
    function parseSpacingValue(value: string): number {
      // Convert rem to px (assuming 1rem = 16px)
      if (value.endsWith('rem')) {
        return parseFloat(value) * 16;
      }
      if (value.endsWith('px')) {
        return parseFloat(value);
      }
      if (value === '0') {
        return 0;
      }
      return NaN;
    }

    it('should follow 8px base grid for component spacing', () => {
      const componentSpacing = tokens.semantic.spacing.component;
      const violations: string[] = [];

      for (const [key, token] of Object.entries(componentSpacing)) {
        if (token && typeof token === 'object' && token.value) {
          // Resolve reference if needed
          let value = token.value;
          if (typeof value === 'string' && value.startsWith('{')) {
            const refPath = value.slice(1, -1).split('.');
            let current = tokens;
            for (const part of refPath) {
              current = current[part];
            }
            value = current.value;
          }

          const pixelValue = parseSpacingValue(value);
          if (!isNaN(pixelValue) && pixelValue > 0) {
            // Allow 4px (0.25rem) as it's half of 8px base unit
            if (pixelValue !== 4 && pixelValue % 8 !== 0) {
              violations.push(`${key}: ${value} (${pixelValue}px) doesn't follow 8px grid`);
            }
          }
        }
      }

      expect(violations).toEqual([]);
    });

    it('should follow 8px multiples for layout spacing', () => {
      const layoutSpacing = tokens.semantic.spacing.layout;
      const violations: string[] = [];

      for (const [key, token] of Object.entries(layoutSpacing)) {
        if (token && typeof token === 'object' && token.value) {
          let value = token.value;
          if (typeof value === 'string' && value.startsWith('{')) {
            const refPath = value.slice(1, -1).split('.');
            let current = tokens;
            for (const part of refPath) {
              current = current[part];
            }
            value = current.value;
          }

          const pixelValue = parseSpacingValue(value);
          if (!isNaN(pixelValue) && pixelValue > 0 && pixelValue % 8 !== 0) {
            violations.push(`${key}: ${value} (${pixelValue}px) doesn't follow 8px grid`);
          }
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('WCAG Accessibility', () => {
    // Convert hex to RGB
    function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
      const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
      return result
        ? {
            r: parseInt(result[1], 16),
            g: parseInt(result[2], 16),
            b: parseInt(result[3], 16),
          }
        : null;
    }

    // Calculate relative luminance
    function getLuminance(rgb: { r: number; g: number; b: number }): number {
      const { r, g, b } = rgb;
      const [rs, gs, bs] = [r, g, b].map((c) => {
        c = c / 255;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
    }

    // Calculate contrast ratio
    function getContrastRatio(color1: string, color2: string): number {
      const rgb1 = hexToRgb(color1);
      const rgb2 = hexToRgb(color2);

      if (!rgb1 || !rgb2) return 0;

      const lum1 = getLuminance(rgb1);
      const lum2 = getLuminance(rgb2);

      const brightest = Math.max(lum1, lum2);
      const darkest = Math.min(lum1, lum2);

      return (brightest + 0.05) / (darkest + 0.05);
    }

    function resolveColorValue(tokenValue: string): string {
      if (tokenValue.startsWith('#')) {
        return tokenValue;
      }

      if (tokenValue.startsWith('{') && tokenValue.endsWith('}')) {
        const path = tokenValue.slice(1, -1).split('.');
        let current = tokens;
        for (const part of path) {
          current = current[part];
        }
        return resolveColorValue(current.value);
      }

      return tokenValue;
    }

    it('should meet WCAG AA contrast for primary text on canvas background', () => {
      const textColor = resolveColorValue(tokens.semantic.colors.text.primary.value);
      const bgColor = resolveColorValue(tokens.semantic.colors.background.canvas.value);

      const contrast = getContrastRatio(textColor, bgColor);
      expect(contrast).toBeGreaterThanOrEqual(4.5); // WCAG AA standard
    });

    it('should meet WCAG AA contrast for secondary text on canvas background', () => {
      const textColor = resolveColorValue(tokens.semantic.colors.text.secondary.value);
      const bgColor = resolveColorValue(tokens.semantic.colors.background.canvas.value);

      const contrast = getContrastRatio(textColor, bgColor);
      expect(contrast).toBeGreaterThanOrEqual(4.5);
    });

    it('should meet WCAG AA contrast for primary text on surface background', () => {
      const textColor = resolveColorValue(tokens.semantic.colors.text.primary.value);
      const bgColor = resolveColorValue(tokens.semantic.colors.background.surface.value);

      const contrast = getContrastRatio(textColor, bgColor);
      expect(contrast).toBeGreaterThanOrEqual(4.5);
    });

    it('should meet WCAG AA contrast for dark theme primary text', () => {
      const darkTextColor = resolveColorValue(tokens.dark.colors.text.primary.value);
      const darkBgColor = resolveColorValue(tokens.dark.colors.background.canvas.value);

      const contrast = getContrastRatio(darkTextColor, darkBgColor);
      expect(contrast).toBeGreaterThanOrEqual(4.5);
    });

    it('should meet WCAG AA contrast for state colors', () => {
      const states = ['success', 'warning', 'error', 'info'];
      const violations: string[] = [];

      for (const state of states) {
        const stateColor = resolveColorValue(tokens.semantic.colors.states[state].value);
        const canvasColor = resolveColorValue(tokens.semantic.colors.background.canvas.value);

        const contrast = getContrastRatio(stateColor, canvasColor);
        if (contrast < 3.0) {
          // Lower threshold for state colors
          violations.push(`${state}: ${contrast.toFixed(2)} (should be >= 3.0)`);
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('Component Token Consistency', () => {
    it('should have consistent button tokens', () => {
      // Check if semantic radii and shadows have button variants
      expect(tokens.semantic.radii).toHaveProperty('button');
      expect(tokens.semantic.shadows).toHaveProperty('button');

      // Verify they reference global tokens
      expect(tokens.semantic.radii.button.value).toMatch(/^\{global\./);
      expect(tokens.semantic.shadows.button.value).toMatch(/^\{global\./);
    });

    it('should have consistent card tokens', () => {
      expect(tokens.semantic.radii).toHaveProperty('card');
      expect(tokens.semantic.shadows).toHaveProperty('card');

      expect(tokens.semantic.radii.card.value).toMatch(/^\{global\./);
      expect(tokens.semantic.shadows.card.value).toMatch(/^\{global\./);
    });

    it('should have all required semantic spacing categories', () => {
      expect(tokens.semantic.spacing).toHaveProperty('component');
      expect(tokens.semantic.spacing).toHaveProperty('layout');

      // Check component spacing has all sizes
      const componentSpacing = tokens.semantic.spacing.component;
      expect(componentSpacing).toHaveProperty('xs');
      expect(componentSpacing).toHaveProperty('sm');
      expect(componentSpacing).toHaveProperty('md');
      expect(componentSpacing).toHaveProperty('lg');
      expect(componentSpacing).toHaveProperty('xl');
    });
  });

  describe('Performance & Bundle Impact', () => {
    it('should not have excessive token nesting depth', () => {
      function getMaxDepth(obj: any, currentDepth = 0): number {
        if (typeof obj !== 'object' || obj === null) {
          return currentDepth;
        }

        let maxChildDepth = currentDepth;
        for (const key in obj) {
          if (key.startsWith('$')) continue; // Skip metadata
          maxChildDepth = Math.max(maxChildDepth, getMaxDepth(obj[key], currentDepth + 1));
        }

        return maxChildDepth;
      }

      const maxDepth = getMaxDepth(tokens);
      expect(maxDepth).toBeLessThanOrEqual(6); // Reasonable limit for performance
    });

    it('should have reasonable token count for bundle size', () => {
      function countTokens(obj: any): number {
        let count = 0;

        for (const [key, value] of Object.entries(obj)) {
          if (key.startsWith('$')) continue; // Skip metadata

          if (value && typeof value === 'object') {
            if (value.type !== undefined) {
              count++; // This is a token
            } else {
              count += countTokens(value); // Recurse
            }
          }
        }

        return count;
      }

      const tokenCount = countTokens(tokens);
      expect(tokenCount).toBeGreaterThan(100); // Should have substantial tokens
      expect(tokenCount).toBeLessThan(1000); // But not excessive for bundle size
    });
  });
});
