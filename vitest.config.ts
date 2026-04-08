import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["test/sdk/**/*.test.ts"],
    testTimeout: 180_000,
    hookTimeout: 120_000,
    sequence: { concurrent: false },
    fileParallelism: false,
  },
});
