/**
 * Vitest Configuration
 * Test configuration for CoreFlow360
 */

import { defineConfig } from 'vitest/config'
// import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [],
  test: {
    // Use node environment for basic testing (miniflare causes issues)
    environment: 'node',
    setupFiles: ['./tests/setup.ts'],
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
          branches: 90,
          functions: 90,
          lines: 95,
          statements: 95
        }
      }
    },
    // Enhanced test execution configuration
    testTimeout: 30000,
    hookTimeout: 30000,
    teardownTimeout: 10000,
    isolate: true,
    threads: true,
    maxThreads: 4,
    minThreads: 1,
    retry: 2,
    bail: 5,
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