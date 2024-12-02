import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";
import stylistic from '@stylistic/eslint-plugin';


/** @type {import('eslint').Linter.Config[]} */
export default [
    {
        ignores: [
            '**/.vscode-test',
            '**/out',
        ]
    },
    { languageOptions: { globals: globals.browser } },
    pluginJs.configs.recommended,
    ...tseslint.configs.recommended,
    ...tseslint.configs.stylistic,
    {
        plugins: {
            '@stylistic': stylistic
        },
        rules: {
            'curly': 'warn',
            '@stylistic/semi': ['warn', 'always'],
            '@typescript-eslint/no-empty-function': 'off',
            '@typescript-eslint/naming-convention': [
                'warn',
                {
                    'selector': 'import',
                    'format': ['camelCase', 'PascalCase']
                }
            ],
            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    'argsIgnorePattern': '^_'
                }
            ]
        }
    }
];
