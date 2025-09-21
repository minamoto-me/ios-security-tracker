module.exports = {
  parser: '@typescript-eslint/parser',
  extends: [
    'eslint:recommended',
  ],
  plugins: ['@typescript-eslint'],
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  env: {
    browser: true,
    es6: true,
    node: true,
  },
  globals: {
    // Cloudflare Workers types
    D1Database: 'readonly',
    KVNamespace: 'readonly',
    ExecutionContext: 'readonly',
    ScheduledController: 'readonly',
    ScheduledEvent: 'readonly',
    ExportedHandler: 'readonly',
  },
  rules: {
    '@typescript-eslint/no-unused-vars': 'error',
    '@typescript-eslint/no-explicit-any': 'warn',
    'prefer-const': 'error',
    'no-var': 'error',
    'no-undef': 'off', // Turn off no-undef since TypeScript handles this
  },
};