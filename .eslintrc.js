module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
    node: true,
    worker: true,
  },
  globals: {
    // Cloudflare Workers globals
    fetch: 'readonly',
    Request: 'readonly',
    Response: 'readonly',
    Headers: 'readonly',
    URL: 'readonly',
    URLSearchParams: 'readonly',
    FormData: 'readonly',
    Blob: 'readonly',
    File: 'readonly',
    ReadableStream: 'readonly',
    WritableStream: 'readonly',
    TransformStream: 'readonly',
    crypto: 'readonly',
    SubtleCrypto: 'readonly',
    CryptoKey: 'readonly',
    TextEncoder: 'readonly',
    TextDecoder: 'readonly',
    atob: 'readonly',
    btoa: 'readonly',
    setTimeout: 'readonly',
    setInterval: 'readonly',
    clearTimeout: 'readonly',
    clearInterval: 'readonly',
    queueMicrotask: 'readonly',
    structuredClone: 'readonly',
    performance: 'readonly',
    console: 'readonly',
    // WebGPU globals (for browser-based AI acceleration)
    navigator: 'readonly',
    window: 'readonly',
    document: 'readonly',
    GPUDevice: 'readonly',
    GPUAdapter: 'readonly',
    GPUComputePipeline: 'readonly',
    GPUBuffer: 'readonly',
    GPUBufferUsage: 'readonly',
    GPUMapMode: 'readonly',
    GPUQuerySet: 'readonly',
  },
  extends: [
    'eslint:recommended',
    'plugin:security/recommended', // Security best practices
  ],
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  plugins: [
    'security',
    'no-secrets',
    'no-unsanitized',
  ],
  rules: {
    // Basic rules
    'no-console': 'warn',
    'no-debugger': 'warn',
    'prefer-const': 'warn',
    'no-var': 'error',
    'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],

    // Security Rules - Critical for Production
    'security/detect-object-injection': 'warn', // Prototype pollution
    'security/detect-non-literal-regexp': 'warn', // ReDoS prevention
    'security/detect-unsafe-regex': 'error', // ReDoS prevention
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'warn',
    'security/detect-disable-mustache-escape': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-no-csrf-before-method-override': 'error',
    'security/detect-non-literal-fs-filename': 'warn',
    'security/detect-non-literal-require': 'warn',
    'security/detect-possible-timing-attacks': 'warn',
    'security/detect-pseudoRandomBytes': 'error',

    // Secret Detection
    'no-secrets/no-secrets': ['error', {
      'tolerance': 4.5, // Lower = stricter
      'additionalRegexes': {
        'Basic Auth': 'Authorization:\\s*Basic\\s+[A-Za-z0-9+/=]+',
        'AWS Key': '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'Stripe Key': '(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}',
      }
    }],

    // XSS Prevention
    'no-unsanitized/method': 'error',
    'no-unsanitized/property': 'error',

    // Relaxed rules for large codebase migration
    'no-redeclare': 'off', // TypeScript handles this
    'no-unused-expressions': 'off',
  },
  overrides: [
    {
      files: ['**/*.ts', '**/*.tsx'],
      rules: {
        'no-undef': 'off', // TypeScript handles undefined variables
      },
    },
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