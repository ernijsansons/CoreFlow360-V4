import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  test: {
    name: 'token-tests',
    globals: true,
    environment: 'node',
    include: [
      'tests/tokens/**/*.test.{ts,js}',
      'tests/tokens/**/*.spec.{ts,js}',
    ],
    exclude: [
      'node_modules/**',
      'dist/**', 
      '.git/**',
      'build/**',
      'coverage/**',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage/tokens',
      exclude: [
        'coverage/**',
        'dist/**',
        'node_modules/**',
        'tests/**',
        '*.config.{js,ts}',
        '**/*.d.ts',
      ],
    },
    reporters: ['default'],
    testTimeout: 30000,
    hookTimeout: 15000,
    // CRITICAL: These settings fix ESM issues
    pool: 'forks',
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    isolate: true,
    // CRITICAL: Prevents vite conflicts
    server: {
      deps: {
        external: ['vite'],
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@tokens': path.resolve(__dirname, './design-system'),
      '@components': path.resolve(__dirname, './frontend/src/components'),
    },
  },
  // CRITICAL: Correct esbuild target for Node 18
  esbuild: {
    target: 'node18',
  },
  // CRITICAL: Optimize for Node 18 compatibility
  optimizeDeps: {
    exclude: ['vite'],
  },
})