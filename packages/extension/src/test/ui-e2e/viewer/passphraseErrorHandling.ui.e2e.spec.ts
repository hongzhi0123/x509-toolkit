import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  stepDelay,
  type VscodeUiSession,
} from '../helpers/vscodeUiHarness';
import { ViewerPage } from '../helpers/viewer/viewerActions';
import { PassphraseDialog } from '../helpers/passphraseDialogActions';

const FIXTURES_DIR = path.resolve(__dirname, '../../../../test-fixtures');
const P12_FILENAME = 'test-rsa-2048.p12';

test.describe.serial('viewer passphrase error handling', () => {
  let session: VscodeUiSession;

  test.beforeAll(async () => {
    session = await launchVscodeForUiE2E();
  });

  test.afterAll(async () => {
    await closeVscodeUiSession(session);
  });

  test('shows error when wrong passphrase is submitted', async () => {
    const { page } = session;
    const viewer = await ViewerPage.openFromExplorer(page, P12_FILENAME);

    const dialog = await PassphraseDialog.waitFor(viewer.frame);
    await stepDelay(page, 'Submitting wrong passphrase');
    await dialog.fillPassphrase('wrong-password');
    await dialog.submit();

    await dialog.waitForHidden();
    await viewer.waitForState('error');

    const errorMsg = await viewer.getErrorMessage();
    expect(errorMsg).toMatch(/password|incorrect|fail|error|decrypt/i);
  });

  test('shows error when passphrase dialog is cancelled', async () => {
    const { page } = session;
    const viewer = await ViewerPage.openFromExplorer(page, P12_FILENAME);

    const dialog = await PassphraseDialog.waitFor(viewer.frame);
    await stepDelay(page, 'Cancelling passphrase dialog');
    await dialog.cancel();

    await dialog.waitForHidden();
    await viewer.waitForState('error');

    const errorMsg = await viewer.getErrorMessage();
    expect(errorMsg).toBeTruthy();
  });
});
