import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  runCommandFromPalette,
  waitForWebviewFrameByTestId,
  type VscodeUiSession,
} from './helpers/vscodeUiHarness';

test.describe('true UI E2E: create certificate flow', () => {
  let session: VscodeUiSession;

  test.beforeAll(async () => {
    const workspacePath = path.resolve(__dirname, '../../../../../');
    session = await launchVscodeForUiE2E(workspacePath);
  });

  test.afterAll(async () => {
    await closeVscodeUiSession(session);
  });

  test('opens create certificate panel and drives CSR workflow via real UI interactions', async () => {
    const { page } = session;

    await runCommandFromPalette(page, 'X.509 Toolkit: Create Certificate');
    await page.keyboard.press('Escape');

    const createFrame = await waitForWebviewFrameByTestId(page, 'create-cert-root');

    await createFrame.getByTestId('create-cert-cn').fill('ui-e2e.example');
    await expect(createFrame.getByTestId('create-cert-cn')).toHaveValue('ui-e2e.example');
    await createFrame.getByTestId('create-cert-signing-csr').check({ force: true });
    await expect(createFrame.getByTestId('create-cert-signing-csr')).toBeChecked();
    await createFrame.getByTestId('create-cert-generate').click({ force: true });
    await expect(createFrame.getByTestId('create-cert-generate')).toBeVisible();
  });
});
