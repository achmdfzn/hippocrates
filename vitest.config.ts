import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    exclude: ["node_modules", "dist"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts", "!src/__tests__/**"],
      reporter: ["text", "lcov"],
      reportsDirectory: "./coverage",
    },
  },
});
