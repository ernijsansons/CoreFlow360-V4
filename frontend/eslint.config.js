// For more info, see https://github.com/storybookjs/eslint-plugin-storybook#configuration-flat-config-format
import storybook from "eslint-plugin-storybook";

import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'
import importPlugin from 'eslint-plugin-import'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs['recommended-latest'],
      reactRefresh.configs.vite,
    ],
    plugins: {
      import: importPlugin,
    },
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      // Prevent circular dependencies - Phase 1.4
      'import/no-restricted-paths': ['error', {
        zones: [
          {
            target: './src/stores',
            from: './src/hooks',
            message: 'Stores cannot import from hooks - creates circular dependency risk'
          },
          {
            target: './src/stores',
            from: './src/components',
            message: 'Stores cannot import from components - creates circular dependency risk'
          },
          {
            target: './src/hooks',
            from: './src/components',
            message: 'Hooks cannot import from components - creates circular dependency risk'
          }
        ]
      }]
    }
  },
])
