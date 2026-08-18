import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  runCommandFromPalette,
  waitForWebviewFrameByTestId,
  dismissNotifications,
  stubSaveDialog,
  stepDelay,
  type VscodeUiSession,
  FIXTURES_DIR,
} from '../helpers/vscodeUiHarness';

const SAVED_P12 = 'ui-e2e-self-signed.p12';
const SAVED_P12_PATH = path.join(FIXTURES_DIR, SAVED_P12);
const CERT_CN = 'self-signed-test.example';
const PASSPHRASE = 'test-passphrase';

test.describe.serial('true UI E2E: create and open P12 certificate', () => {
  let session: VscodeUiSession;

  test.beforeAll(async () => {
    session = await launchVscodeForUiE2E();
    await stubSaveDialog(session.app, SAVED_P12_PATH);
  });

  test.afterAll(async () => {
    await closeVscodeUiSession(session);
    // Remove the file created during the test
    try { fs.unlinkSync(SAVED_P12_PATH); } catch { /* already gone */ }
  });

  test('generates a self-signed P12 certificate and saves it to the workspace', async () => {
    const { page } = session;

    await stepDelay(page, 'Opening Create Certificate panel');
    await runCommandFromPalette(page, 'X.509 Toolkit: Create Certificate');

    await stepDelay(page, 'Waiting for create-cert webview');
    const createFrame = await waitForWebviewFrameByTestId(page, 'create-cert-root');

    await stepDelay(page, 'Filling in CN');
    await createFrame.getByTestId('create-cert-cn').fill(CERT_CN);
    await expect(createFrame.getByTestId('create-cert-cn')).toHaveValue(CERT_CN);

    await stepDelay(page, 'Setting P12 password');
    await createFrame.getByTestId('create-cert-p12-password').fill(PASSPHRASE);
    await createFrame.getByTestId('create-cert-p12-password-confirm').fill(PASSPHRASE);

    await stepDelay(page, 'Clicking Generate button');
    await createFrame.getByTestId('create-cert-generate').click();

    // Save dialog is stubbed in beforeAll — no interaction needed

    await stepDelay(page, 'Waiting for viewer panel with certificate content');
    const viewerFrame = await waitForWebviewFrameByTestId(page, 'viewer-root', 60_000);
    await expect(viewerFrame.getByTestId('viewer-state-ready')).toBeVisible({ timeout: 15_000 });
    await expect(viewerFrame.locator('.cert-cn')).toContainText(CERT_CN, { timeout: 15_000 });
  });

  test('opens the saved P12 certificate from the explorer and validates it', async () => {
    const { page } = session;

    await stepDelay(page, 'Opening Explorer view');
    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+Shift+E' : 'Control+Shift+E');
    await page.waitForTimeout(2000);

    await stepDelay(page, 'Locating the saved P12 file in tree');
    const explorerFile = page.locator('.explorer-viewlet [role="treeitem"]').filter({ hasText: 'ui-e2e-self-signed' }).first();
    await explorerFile.waitFor({ state: 'visible', timeout: 20_000 });

    // await dismissNotifications(page);

    await stepDelay(page, 'Right-clicking via keyboard');
    await explorerFile.click();
    await page.keyboard.press('Shift+F10');

    const openWithToolkit = page.getByRole('menuitem', { name: /Open with X\.509 Toolkit/i }).first();
    await openWithToolkit.waitFor({ state: 'visible', timeout: 15_000 });
    await page.waitForTimeout(300);
    await openWithToolkit.click({ force: true });

    await stepDelay(page, 'Waiting for webview viewer');
    const viewerFrame = await waitForWebviewFrameByTestId(page, 'viewer-root', 45_000);

    await stepDelay(page, 'Typing passphrase into dialog');
    await expect(viewerFrame.getByTestId('passphrase-dialog')).toBeVisible();
    await viewerFrame.getByTestId('passphrase-input').click();
    await viewerFrame.getByTestId('passphrase-input').type(PASSPHRASE);
    await viewerFrame.getByTestId('passphrase-toggle-visibility').click();
    await viewerFrame.getByTestId('passphrase-submit').click();

    await stepDelay(page, 'Asserting viewer shows certificate data');
    await expect(viewerFrame.getByTestId('viewer-state-ready')).toBeVisible({ timeout: 15_000 });
    await expect(viewerFrame.locator('.cert-cn')).toContainText(CERT_CN, { timeout: 15_000 });
  });
});
