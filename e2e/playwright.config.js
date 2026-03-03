const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests",
  timeout: 120_000,
  expect: {
    timeout: 30_000
  },
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI
    ? [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]]
    : [["list"]],
  use: {
    headless: true,
    baseURL: process.env.BASE_URL || "http://localhost:4100"
  }
});
