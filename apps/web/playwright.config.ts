import { defineConfig, devices } from '@playwright/test';

const remoteBaseUrl = process.env.PLAYWRIGHT_BASE_URL;
const baseURL = remoteBaseUrl ?? 'http://127.0.0.1:3000';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 3,
  timeout: remoteBaseUrl ? 60_000 : 30_000,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    reducedMotion: 'reduce',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: remoteBaseUrl ? undefined : {
    command: 'pnpm preview',
    url: 'http://127.0.0.1:3000/en/',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
