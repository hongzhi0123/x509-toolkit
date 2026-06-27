import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { ElectronApplication, Page, Frame } from '@playwright/test';
import { _electron as electron } from '@playwright/test';
import { downloadAndUnzipVSCode } from '@vscode/test-electron';

const STEP_DELAY_MS = parseInt(process.env.UI_E2E_STEP_DELAY ?? '0', 10);

export async function stepDelay(page: Page, label: string): Promise<void> {
  if (STEP_DELAY_MS > 0) {
    console.log(`  [step] ${label} (pause ${STEP_DELAY_MS}ms)...`);
    await page.waitForTimeout(STEP_DELAY_MS);
  }
}

export type VscodeUiSession = {
  app: ElectronApplication;
  page: Page;
  userDataDir: string;
};

export async function launchVscodeForUiE2E(workspacePath: string): Promise<VscodeUiSession> {
  const vscodeExecutablePath = await downloadAndUnzipVSCode('1.126.0');
  const extensionPath = path.resolve(__dirname, '../../../../');
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x509-vscode-ui-e2e-'));
  const extensionsDir = path.join(userDataDir, 'extensions');
  fs.mkdirSync(extensionsDir, { recursive: true });
  // Pre-configure settings to avoid notification popups
  const userSettingsDir = path.join(userDataDir, 'User');
  fs.mkdirSync(userSettingsDir, { recursive: true });
  fs.writeFileSync(
    path.join(userSettingsDir, 'settings.json'),
    JSON.stringify({ 'git.enabled': false, 'gitlens.enabled': false }),
    'utf8'
  );

  const app = await electron.launch({
    executablePath: vscodeExecutablePath,
    args: [
      workspacePath,
      `--extensionDevelopmentPath=${extensionPath}`,
      `--user-data-dir=${userDataDir}`,
      '--skip-welcome',
      '--skip-release-notes',
      '--disable-updates',
      '--disable-workspace-trust',
      `--extensions-dir=${extensionsDir}`,
      '--new-window',
    ],
  });

  const page = await app.firstWindow();
  await page.waitForSelector('.monaco-workbench', { timeout: 60_000 });

  // Open dummy.txt so column One has real content (prevents VS Code from creating Untitled files)
  // await stepDelay(page, 'Opening dummy.txt via Quick Open');
  // try {
  //   await openQuickOpenFile(page, 'dummy.txt', 5_000);
  // } catch {
  //   await page.keyboard.press('Escape');
  // }

  // Close right-side panels (Copilot Chat, etc.) for more room
  await closeRightSidePanels(page);

  return { app, page, userDataDir };
}

export async function closeVscodeUiSession(session: VscodeUiSession): Promise<void> {
  if (STEP_DELAY_MS > 0) {
    console.log('  [step] Closing VS Code session...');
  }

  await session.app.close();
  fs.rmSync(session.userDataDir, { recursive: true, force: true });
}

export async function dismissNotifications(page: Page): Promise<void> {
  // Attempt to clear via command palette
  try {
    await runCommandFromPalette(page, 'Notifications: Clear All', 5_000);
  } catch {
    // If the command palette fails (e.g. modal dialog blocking), fall through
  }
  // Aggressively dismiss any open dialogs/toasts with Escape
  for (let i = 0; i < 10; i++) {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(200);
  }
}

export async function runCommandFromPalette(page: Page, commandTitle: string, itemTimeout = 15_000): Promise<void> {
  console.log(`  [palette] executing: ${commandTitle}`);
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+P' : 'Control+P');
  const widget = page.locator('.quick-input-widget');
  await widget.waitFor({ timeout: 15_000 });
  const input = widget.locator('input.input');
  await input.fill(`>${commandTitle}`);

  await stepDelay(page, `Waiting for command palette item: ${commandTitle}`);

  const exactItem = widget.locator('.quick-input-list .monaco-list-row').filter({ hasText: commandTitle }).first();
  await exactItem.waitFor({ state: 'visible', timeout: itemTimeout });
  await exactItem.click();
  await page.waitForTimeout(250);
  if (await widget.isVisible()) {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(100);
  }
}

export async function openQuickOpenFile(page: Page, fileName: string, itemTimeout = 15_000): Promise<void> {
  console.log(`  [quickopen] opening file: ${fileName}`);
  // Quick Open (Ctrl+P, no '>' prefix) to find and open a file
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+P' : 'Control+P');
  const widget = page.locator('.quick-input-widget');
  await widget.waitFor({ timeout: 15_000 });
  const input = widget.locator('input.input');
  await input.fill(fileName);

  const fileItem = widget.locator('.quick-input-list .monaco-list-row').filter({ hasText: fileName }).first();
  await fileItem.waitFor({ state: 'visible', timeout: itemTimeout });
  await fileItem.click();
  await page.waitForTimeout(250);
  if (await widget.isVisible()) {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(100);
  }
}

export async function closeRightSidePanels(page: Page): Promise<void> {
  // Close the secondary/auxiliary sidebar (Copilot Chat lives there)
  await stepDelay(page, 'Running: View > Toggle Secondary Side Bar');
  try {
    await runCommandFromPalette(page, 'View: Toggle Secondary Side Bar', 5_000);
  } catch {
    // Might not be open; that's fine
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
