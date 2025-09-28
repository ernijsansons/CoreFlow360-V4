/**
 * Vitest Configuration - Fixed
 * Test configuration for CoreFlow360 with MSW integration
 */

import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  plugins: [],
  test: {
    // Use node environment for basic testing
    environment: 'node',
    setupFiles: ['./tests/setup-enhanced.ts'],
    globals: true,
    css: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/',
        'tests/',
        'testing/framework/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/index.ts',
        '**/*.stories.*',
        'dist/',
        'coverage/',
        '.next/',
        'public/',
        '**/*.test.*',
        '**/*.spec.*'
      ],
      thresholds: {
        global: {
          branches: 80,
          functions: 80,
          lines: 85,
          statements: 85
        }
      }
    },
    // Enhanced test execution configuration for stability
    testTimeout: 10000,
    hookTimeout: 10000,
    teardownTimeout: 5000,
    isolate: true,
    threads: false, // Disable threading for MSW compatibility
    retry: 1, // Reduce retries for faster feedback
    bail: 10,
    include: [
      'src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}',
      'tests/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'
    ],
    exclude: [
      'node_modules/',
      'dist/',
      '.next/',
      'coverage/',
      '**/*.config.*',
      '**/*.d.ts'
    ]
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@/components': path.resolve(__dirname, './src/components'),
      '@/lib': path.resolve(__dirname, './src/lib'),
      '@/hooks': path.resolve(__dirname, './src/hooks'),
      '@/stores': path.resolve(__dirname, './src/stores'),
      '@/types': path.resolve(__dirname, './src/types'),
      '@/utils': path.resolve(__dirname, './src/lib/utils')
    }
  }
})