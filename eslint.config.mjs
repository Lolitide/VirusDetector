import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: ["node_modules/", "dist/"],
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.webextensions,
      },
    },
    rules: {
      ...js.configs.recommended.rules,
      // Establish CI without mixing an existing codebase-wide cleanup into this change.
      "no-case-declarations": "off",
      "no-empty": "off",
      "no-prototype-builtins": "off",
      "no-unreachable": "off",
      "no-unused-vars": "off",
      "no-useless-escape": "off",
    },
  },
];
