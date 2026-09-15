import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: "line",
  use: {
    baseURL: "http://127.0.0.1:4173",
    permissions: ["clipboard-read", "clipboard-write"],
    trace: "on-first-retry"
  },
  webServer: {
    command: "node tests/static-server.mjs",
    url: "http://127.0.0.1:4173/copycat/",
    reuseExistingServer: !process.env.CI
  }
});
