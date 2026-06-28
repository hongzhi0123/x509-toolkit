import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  waitForWebviewFrameByTestId,
  dismissNotifications,
  stepDelay,
  type VscodeUiSession,
} from '../helpers/vscodeUiHarness';

const FIXTURES_DIR = path.resolve(__dirname, '../../../test-fixtures');
const P12_FILENAME = 'test-rsa-2048.p12';
const PASSPHRASE = 'test-passphrase';
const CERT_CN = 'test-rsa-2048.example';

test.describe('true UI E2E: open file + passphrase flow', () => {
  let session: VscodeUiSession;

  test.beforeAll(async () => {
    session = await launchVscodeForUiE2E();
  });

  test.afterAll(async () => {
    await closeVscodeUiSession(session);
  });

  test('opens encrypted P12 from explorer and submits passphrase in webview dialog using UI actions', async () => {
    const { page } = session;

    await stepDelay(page, 'Opening Explorer view');
    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+Shift+E' : 'Control+Shift+E');
    await page.waitForTimeout(2000);

    await stepDelay(page, 'Locating the P12 file in tree');
    const explorerFile = page.locator('.explorer-viewlet [role="treeitem"]').filter({ hasText: 'test-rsa-2048' }).first();
    await explorerFile.waitFor({ state: 'visible', timeout: 20_000 });

    // await stepDelay(page, 'Dismiss notifications before right-click');
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
    await expect(viewerFrame.getByTestId('viewer-state-ready')).toBeVisible();
    await expect(viewerFrame.locator('.cert-cn')).toContainText(CERT_CN);

    await stepDelay(page, 'Waiting before clossing VS Code session');
  });
});
