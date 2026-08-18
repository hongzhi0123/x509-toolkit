import * as path from 'path';
import { config } from 'dotenv';

const envPath = path.resolve(__dirname, '../../.env');
config({ path: envPath });

import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './src/test/ui-e2e',
  tsconfig: './tsconfig.playwright.json',
  timeout: 180_000,
  expect: {
    timeout: 30_000,
  },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
});
