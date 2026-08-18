import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  runCommandFromPalette,
  waitForWebviewFrameByTestId,
  stubOpenDialogQueue,
  stubSaveDialogQueue,
  stepDelay,
  FIXTURES_DIR,
} from '../helpers/vscodeUiHarness';
import type { VscodeUiSession } from '../helpers/vscodeUiHarness';

const INPUT_CERT = 'ui-e2e-root-ca.crt';
const OUTPUT_DER = 'ui-e2e-root-ca-converted.der';
const OUTPUT_PEM = 'ui-e2e-root-ca-roundtrip.pem';

const INPUT_CERT_PATH = path.join(FIXTURES_DIR, INPUT_CERT);
const OUTPUT_DER_PATH = path.join(FIXTURES_DIR, OUTPUT_DER);
const OUTPUT_PEM_PATH = path.join(FIXTURES_DIR, OUTPUT_PEM);

test.describe.serial('true UI E2E: convert certificate format', () => {
  let session: VscodeUiSession;

  test.beforeAll(async () => {
    try { fs.unlinkSync(OUTPUT_DER_PATH); } catch { /* already gone */ }
    try { fs.unlinkSync(OUTPUT_PEM_PATH); } catch { /* already gone */ }

    session = await launchVscodeForUiE2E();

    await stubOpenDialogQueue(session.app, [
      INPUT_CERT_PATH,
      OUTPUT_DER_PATH,
    ]);

    await stubSaveDialogQueue(session.app, [
      OUTPUT_DER_PATH,
      OUTPUT_PEM_PATH,
    ]);
  });

  test.afterAll(async () => {
    await closeVscodeUiSession(session);
    try { fs.unlinkSync(OUTPUT_DER_PATH); } catch { /* already gone */ }
    try { fs.unlinkSync(OUTPUT_PEM_PATH); } catch { /* already gone */ }
  });

  test('converts PEM certificate to DER and DER certificate back to PEM', async () => {
    const { page } = session;

    await stepDelay(page, 'Opening Convert Certificate Format command');
    await runCommandFromPalette(page, 'X.509 Toolkit: Convert Certificate Format');

    await stepDelay(page, 'Waiting for Convert Hub webview');
    const convertFrame = await waitForWebviewFrameByTestId(page, 'convert-hub-root', 45_000);

    await stepDelay(page, 'Switching to Convert Format mode');
    await convertFrame.getByRole('tab', { name: /Convert Format/i }).click();

    await stepDelay(page, 'Selecting Certificate PEM to DER conversion');
    await convertFrame.getByRole('button', { name: 'Certificate' }).click();
    await convertFrame.getByRole('button', { name: /PEM/i }).click();

    await stepDelay(page, 'Picking PEM certificate input file');
    await convertFrame.getByRole('button', { name: /Browse/i }).click();
    await expect(convertFrame.locator('.mode-panel .file-name').first()).toContainText(INPUT_CERT);

    await stepDelay(page, 'Executing PEM to DER conversion');
    await convertFrame.locator('.mode-panel .action-row .btn.btn-primary').click();

    const statusArea = convertFrame.locator('.mode-panel .status-area').first();
    await expect(statusArea).toContainText('DER file saved.', { timeout: 15_000 });

    await stepDelay(page, 'Switching to DER to PEM conversion');
    await convertFrame.getByRole('button', { name: /DER/i }).click();

    await stepDelay(page, 'Picking DER certificate input file');
    await convertFrame.getByRole('button', { name: /Browse/i }).click();
    await expect(convertFrame.locator('.mode-panel .file-name').first()).toContainText(OUTPUT_DER);

    await stepDelay(page, 'Executing DER to PEM conversion');
    await convertFrame.locator('.mode-panel .action-row .btn.btn-primary').click();
    await expect(statusArea).toContainText('PEM file saved.', { timeout: 15_000 });

    await expect(fs.existsSync(OUTPUT_DER_PATH)).toBeTruthy();
    await expect(fs.existsSync(OUTPUT_PEM_PATH)).toBeTruthy();

    const derBuffer = fs.readFileSync(OUTPUT_DER_PATH);
    await expect(derBuffer.length).toBeGreaterThan(0);
    await expect(derBuffer.toString('utf8')).not.toContain('BEGIN CERTIFICATE');

    const pemText = fs.readFileSync(OUTPUT_PEM_PATH, 'utf8');
    await expect(pemText).toContain('BEGIN CERTIFICATE');
    await expect(pemText).toContain('END CERTIFICATE');
  });
});
