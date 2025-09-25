import { defineConfig } from 'vitest/config';
import path from 'path';

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
      'node_modules',
      'dist',
      '.git',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'coverage/**',
        'dist/**',
        'node_modules/**',
        'tests/**',
        '*.config.{js,ts}',
      ],
    },
    reporters: ['default'],
    testTimeout: 10000,
    hookTimeout: 10000,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@tokens': path.resolve(__dirname, './design-system'),
      '@components': path.resolve(__dirname, './frontend/src/components'),
    },
  },
});