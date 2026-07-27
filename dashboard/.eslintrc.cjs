/* eslint-env node */
module.exports = {
  root: true,
  env: { browser: true, es2022: true },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended",
    "plugin:jsx-a11y/recommended",
  ],
  parser: "@typescript-eslint/parser",
  parserOptions: { ecmaVersion: "latest", sourceType: "module" },
  plugins: ["react-refresh", "jsx-a11y"],
  ignorePatterns: ["dist", ".eslintrc.cjs", "*.config.js", "*.config.ts"],
  rules: {
    // Icon-only controls and colour-only status encoding are the exact
    // accessibility failures this dashboard cannot afford (operators with
    // colour-vision deficiency read these screens) — jsx-a11y catches the
    // first class of bug at commit time instead of at audit time.
    "react-refresh/only-export-components": [
      "warn",
      { allowConstantExport: true },
    ],
    "@typescript-eslint/no-unused-vars": [
      "error",
      { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
    ],
    "@typescript-eslint/consistent-type-imports": "error",
    "no-console": ["warn", { allow: ["warn", "error"] }],
  },
};
