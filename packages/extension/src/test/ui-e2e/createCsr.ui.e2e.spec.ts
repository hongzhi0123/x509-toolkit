import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  runCommandFromPalette,
  waitForWebviewFrameByTestId,
  stepDelay,
  type VscodeUiSession,
} from './helpers/vscodeUiHarness';

const FIXTURES_DIR = path.resolve(__dirname, '../../../test-fixtures');

test.describe('true UI E2E: create CSR flow', () => {
  let session: VscodeUiSession;

  test.beforeAll(async () => {
    session = await launchVscodeForUiE2E(FIXTURES_DIR);
  });

  test.afterAll(async () => {
    await closeVscodeUiSession(session);
  });

  test('opens Create Certificate panel, selects CSR mode and generates a CSR', async () => {
    const { page } = session;

    await stepDelay(page, 'Running command from palette');
    await runCommandFromPalette(page, 'X.509 Toolkit: Create Certificate');
    await page.keyboard.press('Escape');

    await stepDelay(page, 'Waiting for create-cert webview');
    const createFrame = await waitForWebviewFrameByTestId(page, 'create-cert-root');

    await stepDelay(page, 'Filling in CN and selecting CSR');
    await createFrame.getByTestId('create-cert-cn').fill('ui-e2e.example');
    await expect(createFrame.getByTestId('create-cert-cn')).toHaveValue('ui-e2e.example');
    await stepDelay(page, 'Checking CSR radio button');
    await createFrame.getByTestId('create-cert-signing-csr').check({ force: true });
    await expect(createFrame.getByTestId('create-cert-signing-csr')).toBeChecked();

    await stepDelay(page, 'Clicking Generate button');
    await createFrame.getByTestId('create-cert-generate').click({ force: true });
    await expect(createFrame.getByTestId('create-cert-generate')).toBeVisible();
  });
});
