// @ts-check
import eslint from "@eslint/js";
import prettier from "eslint-config-prettier";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "node_modules/", "*.tgz"] },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Byte parsers index into Uint8Arrays constantly; `!` on a bounds-checked read is clearer than `?? 0`.
      "@typescript-eslint/no-non-null-assertion": "off",
      "@typescript-eslint/restrict-template-expressions": [
        "error",
        { allowNumber: true, allowBoolean: true, allowNullish: true },
      ],
    },
  },
  {
    files: ["test/**"],
    rules: {
      // node:test's test() returns a promise that the runner owns.
      "@typescript-eslint/no-floating-promises": "off",
      // Tests assert on optional report fields; the chains document intent.
      "@typescript-eslint/no-unnecessary-condition": "off",
    },
  },
  { files: ["eslint.config.js"], ...tseslint.configs.disableTypeChecked },
  prettier,
);
