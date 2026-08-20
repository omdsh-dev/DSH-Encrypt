import oxlint from '@mzwing/oxc-config'

export default oxlint({
  ignores: ['lib/**'],
  rules: {
    'node-extra/prefer-global/buffer': 'off',
    'node-extra/prefer-global/process': 'off',
    'jsdoc/no-defaults': 'off',
    'jsdoc/require-returns-description': 'off',
    'jsdoc-extra/check-types': 'off',
    'regexp/prefer-w': 'off',
    'typescript/promise-function-async': 'off',
    'typescript/strict-boolean-expressions': 'off',
    'unicorn/number-literal-case': 'off',
  },
  test: {
    overrides: {
      'typescript/await-thenable': 'off',
      'typescript/no-floating-promises': 'off',
      'typescript/no-unsafe-assignment': 'off',
      'typescript/no-unsafe-call': 'off',
      'typescript/no-unsafe-member-access': 'off',
      'typescript/strict-boolean-expressions': 'off',
    },
  },
  type: 'lib',
  typescript: true,
})
