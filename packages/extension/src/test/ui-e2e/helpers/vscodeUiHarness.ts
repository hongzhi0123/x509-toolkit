import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { ElectronApplication, Page, Frame } from '@playwright/test';
import { _electron as electron } from '@playwright/test';
import { downloadAndUnzipVSCode } from '@vscode/test-electron';

export type VscodeUiSession = {
  app: ElectronApplication;
  page: Page;
  userDataDir: string;
};

export async function launchVscodeForUiE2E(workspacePath: string): Promise<VscodeUiSession> {
  const vscodeExecutablePath = await downloadAndUnzipVSCode('1.126.0');
  const extensionPath = path.resolve(__dirname, '../../../../');
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x509-vscode-ui-e2e-'));

  const app = await electron.launch({
    executablePath: vscodeExecutablePath,
    args: [
      workspacePath,
      `--extensionDevelopmentPath=${extensionPath}`,
      `--user-data-dir=${userDataDir}`,
      '--skip-welcome',
      '--skip-release-notes',
      '--disable-updates',
      '--new-window',
    ],
  });

  const page = await app.firstWindow();
  await page.waitForSelector('.monaco-workbench', { timeout: 60_000 });

  return { app, page, userDataDir };
}

export async function closeVscodeUiSession(session: VscodeUiSession): Promise<void> {
  await session.app.close();
  fs.rmSync(session.userDataDir, { recursive: true, force: true });
}

export async function runCommandFromPalette(page: Page, commandTitle: string): Promise<void> {
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+P' : 'Control+P');
  const widget = page.locator('.quick-input-widget');
  await widget.waitFor({ timeout: 15_000 });
  const input = widget.locator('input.input');
  await input.fill(`>${commandTitle}`);

  const exactItem = widget.locator('.quick-input-list .monaco-list-row').filter({ hasText: commandTitle }).first();
  await exactItem.waitFor({ state: 'visible', timeout: 15_000 });
  await exactItem.dblclick();
  await page.waitForTimeout(250);
  if (await widget.isVisible()) {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(100);
  }
}

export async function waitForWebviewFrameByTestId(page: Page, testId: string, timeoutMs = 30_000): Promise<Frame> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    for (const frame of page.frames()) {
      try {
        const count = await frame.locator(`[data-testid="${testId}"]`).count();
        if (count > 0) {
          return frame;
        }
      } catch {
        // Frame might still be initializing; continue polling.
      }
    }
    await page.waitForTimeout(100);
  }
  throw new Error(`Timed out waiting for webview frame with data-testid="${testId}"`);
}
