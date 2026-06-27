import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  runCommandFromPalette,
  waitForWebviewFrameByTestId,
  dismissNotifications,
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

  test('opens Create Certificate panel, selects CSR mode, generates a CSR, and validates the result', async () => {
    const { page } = session;

    await stepDelay(page, 'Running command from palette');
    await runCommandFromPalette(page, 'X.509 Toolkit: Create Certificate');

    await stepDelay(page, 'Waiting for create-cert webview');
    const createFrame = await waitForWebviewFrameByTestId(page, 'create-cert-root');

    await stepDelay(page, 'Filling in CN and selecting CSR');
    await createFrame.getByTestId('create-cert-cn').fill('ui-e2e.example');
    await expect(createFrame.getByTestId('create-cert-cn')).toHaveValue('ui-e2e.example');

    await stepDelay(page, 'Selecting CSR mode');
    await createFrame.getByTestId('create-cert-signing-csr').check({ force: true });
    await expect(createFrame.getByTestId('create-cert-signing-csr')).toBeChecked();

    await stepDelay(page, 'Wait for notifications to auto-dismiss');
    await page.waitForTimeout(3000);

    await stepDelay(page, 'Clicking Generate button');
    await createFrame.getByTestId('create-cert-generate').click();

    await stepDelay(page, 'Waiting for viewer panel with CSR content');
    const viewerFrame = await waitForWebviewFrameByTestId(page, 'viewer-root', 30_000);
    await expect(viewerFrame.locator('.csr-cn')).toContainText('ui-e2e.example', { timeout: 15_000 });

    await stepDelay(page, 'Waiting before clossing VS Code session');
  });
});
