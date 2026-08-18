import type { Frame, Page } from '@playwright/test';
import { expect } from '@playwright/test';
import { waitForWebviewFrameByTestId, stepDelay, dismissNotifications } from '../vscodeUiHarness';

export type ViewerState = 'idle' | 'loading' | 'ready' | 'error' | 'csr';

function stateTestId(state: ViewerState): string {
  return `viewer-state-${state}`;
}

export class ViewerPage {
  constructor(public readonly frame: Frame) {}

  static async open(page: Page, timeoutMs = 45_000): Promise<ViewerPage> {
    const frame = await waitForWebviewFrameByTestId(page, 'viewer-root', timeoutMs);
    return new ViewerPage(frame);
  }

  static async openFromExplorer(page: Page, fileName: string, openTimeoutMs = 45_000): Promise<ViewerPage> {
    await stepDelay(page, 'Opening Explorer view');
    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+Shift+E' : 'Control+Shift+E');
    await page.waitForTimeout(2000);

    await stepDelay(page, `Locating file "${fileName}" in tree`);
    const explorerFile = page
      .locator('.explorer-viewlet [role="treeitem"]')
      .filter({ hasText: fileName })
      .first();
    await explorerFile.waitFor({ state: 'visible', timeout: 20_000 });

    // await dismissNotifications(page);

    await stepDelay(page, 'Opening context menu via keyboard');
    await explorerFile.click();
    await page.keyboard.press('Shift+F10');

    const openWithToolkit = page
      .getByRole('menuitem', { name: /Open with X\.509 Toolkit/i })
      .first();
    await openWithToolkit.waitFor({ state: 'visible', timeout: 15_000 });
    await page.waitForTimeout(300);
    await openWithToolkit.click({ force: true });

    return await ViewerPage.open(page, openTimeoutMs);
  }

  async waitForState(state: ViewerState, options?: { timeout?: number }): Promise<void> {
    await expect(this.frame.getByTestId(stateTestId(state))).toBeVisible({
      timeout: options?.timeout ?? 15_000,
    });
  }

  async getErrorMessage(): Promise<string> {
    return await this.frame.locator('.error-message').innerText();
  }

  async getCertificateCn(): Promise<string> {
    return await this.frame.locator('.cert-cn').innerText();
  }

  async getCsrCn(): Promise<string> {
    return await this.frame.locator('.csr-cn').innerText();
  }
}
