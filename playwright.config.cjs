const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests/e2e",
  timeout: 30_000,
  expect: {
    timeout: 5_000
  },
  use: {
    baseURL: "http://127.0.0.1:39211",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "cargo run -p harbor-demo",
    url: "http://127.0.0.1:39211/healthz",
    timeout: 30_000,
    reuseExistingServer: false,
    env: {
      HARBOR_DEMO_BROWSER_SMOKE: "1",
      HARBOR_DATABASE_URL: "sqlite::memory:",
      HARBOR_DEMO_ADDR: "127.0.0.1:39211",
      HARBOR_PUBLIC_BASE_URL: "http://127.0.0.1:39211",
      HARBOR_HMAC_KEY: "playwright-recording-smoke-key-32b"
    }
  }
});
