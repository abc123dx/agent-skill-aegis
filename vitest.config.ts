import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      exclude: ["src/cli.ts", "src/types.ts"],
      include: ["src/**/*.ts"],
      provider: "v8",
      reporter: ["text", "html"]
    },
    include: ["tests/**/*.test.ts"]
  }
});
