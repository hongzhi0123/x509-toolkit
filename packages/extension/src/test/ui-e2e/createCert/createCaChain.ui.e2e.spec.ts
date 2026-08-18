import * as crypto from 'crypto';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import type { Frame, Page } from '@playwright/test';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { createP12Buffer } from '@x509-toolkit/core';
import {
  launchVscodeForUiE2E,
  closeVscodeUiSession,
  runCommandFromPalette,
  waitForWebviewFrameByTestId,
  stubOpenDialogQueue,
  stubSaveDialogQueue,
  stepDelay,
  FIXTURES_DIR,
  type VscodeUiSession,
} from '../helpers/vscodeUiHarness';

const ROOT_P12 = 'ui-e2e-root-ca.p12';
const INTERMEDIATE_P12 = 'ui-e2e-intermediate-ca.p12';
const LEAF_P12 = 'ui-e2e-leaf-cert.p12';
const ROOT_CERT_PEM = 'ui-e2e-root-ca.crt';
const ROOT_KEY_PEM = 'ui-e2e-root-ca.key';
const INTERMEDIATE_CERT_PEM = 'ui-e2e-intermediate-ca.crt';
const INTERMEDIATE_KEY_PEM = 'ui-e2e-intermediate-ca.key';

const ROOT_P12_PATH = path.join(FIXTURES_DIR, ROOT_P12);
const INTERMEDIATE_P12_PATH = path.join(FIXTURES_DIR, INTERMEDIATE_P12);
const LEAF_P12_PATH = path.join(FIXTURES_DIR, LEAF_P12);
const ROOT_CERT_PEM_PATH = path.join(FIXTURES_DIR, ROOT_CERT_PEM);
const ROOT_KEY_PEM_PATH = path.join(FIXTURES_DIR, ROOT_KEY_PEM);
const INTERMEDIATE_CERT_PEM_PATH = path.join(FIXTURES_DIR, INTERMEDIATE_CERT_PEM);
const INTERMEDIATE_KEY_PEM_PATH = path.join(FIXTURES_DIR, INTERMEDIATE_KEY_PEM);

const ROOT_CN = 'ui-e2e-root-ca.example';
const INTERMEDIATE_CN = 'ui-e2e-intermediate-ca.example';
const LEAF_CN = 'ui-e2e-leaf.example';
const PASSPHRASE = 'test-passphrase';
const webcrypto = new PeculiarCrypto();

x509.cryptoProvider.set(webcrypto);

async function createLeafP12WithAia(issuerCertPem: string, issuerKeyPem: string, issuerUrl: string): Promise<Buffer> {
  const issuerCert = new x509.X509Certificate(issuerCertPem);
  const issuerKey = crypto.createPrivateKey(issuerKeyPem);
  const issuerPkcs8Der = issuerKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;

  const importedIssuerKey = await webcrypto.subtle.importKey(
    'pkcs8',
    new Uint8Array(issuerPkcs8Der),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const leafKeyPair = await webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  ) as CryptoKeyPair;

  const serialBytes = crypto.randomBytes(16);
  serialBytes[0] &= 0x7f;
  const now = new Date();

  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: serialBytes.toString('hex'),
    subject: `CN=${LEAF_CN}`,
    issuer: issuerCert.subject,
    notBefore: now,
    notAfter: new Date(now.getTime() + 365 * 86_400_000),
    signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5' },
    publicKey: leafKeyPair.publicKey,
    signingKey: importedIssuerKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true
      ),
      new x509.SubjectAlternativeNameExtension([new x509.GeneralName('dns', LEAF_CN)]),
      await x509.SubjectKeyIdentifierExtension.create(leafKeyPair.publicKey, false, webcrypto),
      await x509.AuthorityKeyIdentifierExtension.create(issuerCert.publicKey, false, webcrypto),
      new x509.AuthorityInfoAccessExtension({ caIssuers: [issuerUrl] }),
    ],
  }, webcrypto);

  const leafPkcs8Der = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', leafKeyPair.privateKey) as ArrayBuffer);
  return createP12Buffer([cert.toString('pem')], PASSPHRASE, leafPkcs8Der);
}

async function startIssuerServer(issuerCertPem: string): Promise<{ server: http.Server; issuerUrl: string }> {
  return await new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      if (req.url === '/issuer.crt') {
        res.writeHead(200, {
          'Content-Type': 'application/x-pem-file',
          'Cache-Control': 'no-store',
        });
        res.end(issuerCertPem);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
    });

    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Failed to start issuer server.'));
        return;
      }

      resolve({
        server,
        issuerUrl: `http://127.0.0.1:${address.port}/issuer.crt`,
      });
    });
  });
}

async function openCreateCertPanel(page: Page): Promise<Frame> {
  await stepDelay(page, 'Opening Create Certificate panel');
  await runCommandFromPalette(page, 'X.509 Toolkit: Create Certificate');
  await stepDelay(page, 'Waiting for create-cert webview');
  return await waitForWebviewFrameByTestId(page, 'create-cert-root');
}

async function openActionsMenuAndSelect(viewerFrame: Frame, itemName: string | RegExp): Promise<void> {
  const actionsTrigger = viewerFrame.locator('.actions-trigger').first();
  await actionsTrigger.click();
  await viewerFrame.getByRole('menuitem', { name: itemName }).click();
}

async function openSavedP12FromExplorer(page: Page, fileName: string): Promise<Frame> {
  await stepDelay(page, 'Opening Explorer view');
  await page.keyboard.press(process.platform === 'darwin' ? 'Meta+Shift+E' : 'Control+Shift+E');
  await page.waitForTimeout(2000);

  await stepDelay(page, `Locating ${fileName} in tree`);
  const explorerFile = page.locator('.explorer-viewlet [role="treeitem"]').filter({ hasText: fileName }).first();
  await explorerFile.waitFor({ state: 'visible', timeout: 20_000 });

  await stepDelay(page, 'Opening context menu via keyboard');
  await explorerFile.click();
  await page.keyboard.press('Shift+F10');

  const openWithToolkit = page.getByRole('menuitem', { name: /Open with X\.509 Toolkit/i }).first();
  await openWithToolkit.waitFor({ state: 'visible', timeout: 15_000 });
  await page.waitForTimeout(300);
  await openWithToolkit.click({ force: true });

  return await waitForWebviewFrameByTestId(page, 'viewer-root', 45_000);
}

async function unlockViewerIfNeeded(viewerFrame: Frame): Promise<void> {
  const dialog = viewerFrame.getByTestId('passphrase-dialog');
  if (await dialog.isVisible().catch(() => false)) {
    await dialog.getByTestId?.('passphrase-input');
    await viewerFrame.getByTestId('passphrase-input').click();
    await viewerFrame.getByTestId('passphrase-input').fill(PASSPHRASE);
    await viewerFrame.getByTestId('passphrase-submit').click();
  }
}

test.describe.serial('true UI E2E: create root, intermediate, and leaf certificate chain', () => {
  let session: VscodeUiSession;
  let issuerServer: http.Server | null = null;

  test.beforeAll(async () => {
    session = await launchVscodeForUiE2E();
    await stubSaveDialogQueue(session.app, [
      ROOT_P12_PATH,
      ROOT_CERT_PEM_PATH,
      ROOT_KEY_PEM_PATH,
      INTERMEDIATE_P12_PATH,
      INTERMEDIATE_CERT_PEM_PATH,
      INTERMEDIATE_KEY_PEM_PATH,
      LEAF_P12_PATH,
    ]);
    await stubOpenDialogQueue(session.app, [
      ROOT_CERT_PEM_PATH,
      ROOT_KEY_PEM_PATH,
      INTERMEDIATE_CERT_PEM_PATH,
      INTERMEDIATE_KEY_PEM_PATH,
    ]);
  });

  test.afterAll(async () => {
    await new Promise<void>(resolve => {
      if (!issuerServer) {
        resolve();
        return;
      }
      issuerServer.close(() => resolve());
    });
    await closeVscodeUiSession(session);
    for (const filePath of [ROOT_P12_PATH, INTERMEDIATE_P12_PATH, LEAF_P12_PATH]) {
      try { fs.unlinkSync(filePath); } catch { /* already gone */ }
    }
  });

  test('creates a root CA, an intermediate CA, and a leaf certificate signed by the intermediate', async () => {
    const { page } = session;

    const rootFrame = await openCreateCertPanel(page);
    await rootFrame.getByTestId('create-cert-cn').fill(ROOT_CN);
    await expect(rootFrame.getByTestId('create-cert-cn')).toHaveValue(ROOT_CN);
    await rootFrame.getByTestId('create-cert-is-ca').check({ force: true });
    await rootFrame.getByTestId('create-cert-p12-password').fill(PASSPHRASE);
    await rootFrame.getByTestId('create-cert-p12-password-confirm').fill(PASSPHRASE);
    await rootFrame.getByTestId('create-cert-generate').click();

    const rootViewer = await waitForWebviewFrameByTestId(page, 'viewer-root', 60_000);
    await expect(rootViewer.getByTestId('viewer-state-ready')).toBeVisible({ timeout: 15_000 });
    await expect(rootViewer.locator('.cert-cn')).toContainText(ROOT_CN, { timeout: 15_000 });

    await openActionsMenuAndSelect(rootViewer, /Export as PEM/i);
    await openActionsMenuAndSelect(rootViewer, /Export Private Key/i);

    const intermediateFrame = await openCreateCertPanel(page);
    await intermediateFrame.getByTestId('create-cert-cn').fill(INTERMEDIATE_CN);
    await expect(intermediateFrame.getByTestId('create-cert-cn')).toHaveValue(INTERMEDIATE_CN);
    await intermediateFrame.getByTestId('create-cert-is-ca').check({ force: true });
    await intermediateFrame.getByTestId('create-cert-signing-ca').check({ force: true });
    await intermediateFrame.getByTestId('create-cert-p12-password').fill(PASSPHRASE);
    await intermediateFrame.getByTestId('create-cert-p12-password-confirm').fill(PASSPHRASE);
    await intermediateFrame.getByTestId('create-cert-pick-ca-cert').click();
    await intermediateFrame.getByTestId('create-cert-pick-ca-key').click();
    await intermediateFrame.getByTestId('create-cert-generate').click();

    const intermediateViewer = await openSavedP12FromExplorer(page, INTERMEDIATE_P12);
    await unlockViewerIfNeeded(intermediateViewer);
    await expect(intermediateViewer.getByTestId('viewer-state-ready')).toBeVisible({ timeout: 15_000 });
    await expect(intermediateViewer.locator('.cert-cn')).toContainText(INTERMEDIATE_CN, { timeout: 15_000 });
    await expect(intermediateViewer.locator('.cert-view')).toContainText(ROOT_CN, { timeout: 15_000 });

    await openActionsMenuAndSelect(intermediateViewer, /Export as PEM/i);
    await openActionsMenuAndSelect(intermediateViewer, /Export Private Key/i);

    const issuerServerInfo = await startIssuerServer(
      fs.readFileSync(INTERMEDIATE_CERT_PEM_PATH, 'utf8').trim()
    );
    issuerServer = issuerServerInfo.server;

    const leafP12 = await createLeafP12WithAia(
      fs.readFileSync(INTERMEDIATE_CERT_PEM_PATH, 'utf8').trim(),
      fs.readFileSync(INTERMEDIATE_KEY_PEM_PATH, 'utf8').trim(),
      issuerServerInfo.issuerUrl
    );
    fs.writeFileSync(LEAF_P12_PATH, leafP12);

    const leafViewer = await openSavedP12FromExplorer(page, LEAF_P12);
    await unlockViewerIfNeeded(leafViewer);
    await expect(leafViewer.getByTestId('viewer-state-ready')).toBeVisible({ timeout: 15_000 });
    await expect(leafViewer.locator('.cert-cn')).toContainText(LEAF_CN, { timeout: 15_000 });
    await expect(leafViewer.locator('.cert-view')).toContainText(INTERMEDIATE_CN, { timeout: 15_000 });

    const aiaSection = leafViewer.locator('.ext-item').filter({ hasText: 'Authority Information Access' }).first();
    await aiaSection.getByRole('button', { name: /Authority Information Access/i }).click();
    await expect(aiaSection.locator('.ca-issuer-url')).toContainText(issuerServerInfo.issuerUrl, { timeout: 10_000 });
    await aiaSection.locator('.load-ca-btn').first().click();

    await expect(leafViewer.locator('.cert-cn')).toContainText(INTERMEDIATE_CN, { timeout: 15_000 });
    await expect(leafViewer.locator('[data-testid="viewer-chain-nav"]')).toContainText(INTERMEDIATE_CN, { timeout: 15_000 });

    await stepDelay(page, 'Leaf chain reopened and validated');
  });
});