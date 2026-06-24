import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  waitForWebviewFrameByTestId,
  type VscodeUiSession,
} from './helpers/vscodeUiHarness';

test.describe('true UI E2E: open file + passphrase flow', () => {
  let session: VscodeUiSession;
  let workspacePath: string;
  let p12Path: string;

  const certCommonName = 'ui-open-file.example';
  const passphrase = 'ui-e2e-passphrase';

  test.beforeAll(async () => {
    workspacePath = path.resolve(__dirname, '../../../../../');
    p12Path = path.join(workspacePath, 'ui-e2e-open-file.p12');

    // Load from compiled core output to keep Playwright TS transpilation simple.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { createSelfSignedP12 } = require(path.join(workspacePath, 'packages/core/dist')) as {
      createSelfSignedP12: (commonName: string, days: number, password: string) => Promise<Buffer>;
    };
    const p12Buffer = await createSelfSignedP12(certCommonName, 30, passphrase);
    fs.writeFileSync(p12Path, p12Buffer);

    session = await launchVscodeForUiE2E(workspacePath);
  });

  test.afterAll(async () => {
    await closeVscodeUiSession(session);
    fs.rmSync(p12Path, { force: true });
  });

  test('opens encrypted P12 from explorer and submits passphrase in webview dialog using UI actions', async () => {
    const { page } = session;
    const fileName = path.basename(p12Path);

    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+Shift+E' : 'Control+Shift+E');
    const explorerFile = page
      .locator('[role="treeitem"]')
      .filter({ hasText: fileName })
      .first();
    await explorerFile.waitFor({ state: 'visible', timeout: 20_000 });
    await explorerFile.dblclick();

    await explorerFile.click();
    await page.keyboard.press('Shift+F10');

    const openWithToolkit = page.getByRole('menuitem', { name: /Open with X\.509 Toolkit/i }).first();
    await openWithToolkit.waitFor({ state: 'visible', timeout: 15_000 });
    await openWithToolkit.click();

    const viewerFrame = await waitForWebviewFrameByTestId(page, 'viewer-root');

    await expect(viewerFrame.getByTestId('passphrase-dialog')).toBeVisible();
    await viewerFrame.getByTestId('passphrase-input').click();
    await viewerFrame.getByTestId('passphrase-input').type(passphrase);
    await viewerFrame.getByTestId('passphrase-toggle-visibility').click();
    await viewerFrame.getByTestId('passphrase-submit').click();

    await expect(viewerFrame.getByTestId('viewer-state-ready')).toBeVisible();
    await expect(viewerFrame.locator('.cert-cn')).toContainText(certCommonName);
  });
});