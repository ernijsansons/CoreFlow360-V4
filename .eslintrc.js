module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
    node: true,
    worker: true,
  },
  extends: [
    'eslint:recommended',
  ],
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  plugins: [],
  rules: {
    // Basic rules for initial setup
    'no-console': 'warn',
    'no-debugger': 'warn',
    'prefer-const': 'warn',
    'no-var': 'error',
    'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    
    // Relaxed rules for large codebase migration
    'no-undef': 'off', // TypeScript handles this
    'no-redeclare': 'off', // TypeScript handles this
    'no-unused-expressions': 'off',
  },
  overrides: [
    {
      files: ['**/*.test.ts', '**/*.test.tsx', '**/*.spec.ts'],
      rules: {
        'no-console': 'off',
      },
    },
    {
      files: ['**/*.config.ts', '**/*.config.js'],
      rules: {
        'no-console': 'off',
      },
    },
  ],
  ignorePatterns: [
    'node_modules/',
    'dist/',
    '.wrangler/',
    'coverage/',
    '*.config.js',
    '*.config.ts',
    '__graveyard__/',
  ],
};