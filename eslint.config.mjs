import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", ".wrangler/**", "examples/**"] },
  ...tseslint.configs.recommended,
);
