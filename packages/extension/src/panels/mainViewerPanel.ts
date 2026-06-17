import * as vscode from 'vscode';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';
import { X509Certificate } from '@peculiar/x509';
import { parseCertificate, parsePEMChain, createP12Buffer, loadAndValidatePrivateKey, signCsr, formatIssuerChainFailure, validateIssuerChain, isEncryptedKey } from '@x509-toolkit/core';
import type { CertificateData, CsrData, ExtToWebviewMsg, WebviewToExtMsg, InputDialogFieldDef, TlsConnectionInfo } from '@x509-toolkit/core';
import { requestInputDialog, requestPassphrase, resolveInputDialogRequest, resolvePassphraseRequest } from '../utils/requestBridgeUtils';
import { routeViewerMessage } from '../utils/messageRouterUtils';
import { exportCertificate, exportPrivateKey, savePrivateKeyFromMemory, saveCsrFromMemory, saveCsrAndPrivateKey, type ViewerFileActionHost } from '../utils/fileActionsUtils';
import { importPrivateKey, type KeyImportHost } from '../utils/keyImportUtils';
import { openConvertPanel } from './convertPanel';
import { buildHtml, createMessageQueue } from '../utils/webviewPanelUtils';

let currentPanel: vscode.WebviewPanel | undefined;
let extensionContext: vscode.ExtensionContext;
const viewerQueue = createMessageQueue<ExtToWebviewMsg>();

// CSR PEM and private key held when a CSR is generated via Create Cert panel.
// The key is NEVER sent to the webview; only a description string is passed.
let pendingViewerCsrPem: string | undefined;
let pendingViewerCsrKeyPem: string | undefined;

function createViewerFileActionHost(panel: vscode.WebviewPanel): ViewerFileActionHost {
  return {
    showSaveDialog: async (options) => {
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(options.defaultPath),
        filters: options.filters,
        saveLabel: options.saveLabel,
        title: options.title,
      });
      return uri?.fsPath;
    },
    writeFile: (filePath, data, encoding) => {
      if (typeof data === 'string') {
        fs.writeFileSync(filePath, data, encoding);
        return;
      }
      fs.writeFileSync(filePath, data);
    },
    showInformationMessage: (message) => {
      vscode.window.showInformationMessage(message);
    },
    showWarningMessage: (message) => {
      vscode.window.showWarningMessage(message);
    },
    requestInputDialog: (title, fields, options) => requestInputDialogFromWebview(panel, title, fields, options),
  };
}

function createQueuedWebviewSink(panel: vscode.WebviewPanel): { postMessage(message: unknown): unknown } {
  return {
    postMessage: (message) => {
      viewerQueue.post(panel, message as ExtToWebviewMsg);
    },
  };
}

function createKeyImportHost(panel: vscode.WebviewPanel): KeyImportHost {
  return {
    showOpenDialog: async (options) => {
      const uris = await vscode.window.showOpenDialog({
        canSelectMany: options.canSelectMany,
        openLabel: options.openLabel,
        title: options.title,
        filters: options.filters,
      });
      return uris?.[0]?.fsPath;
    },
    readFile: (filePath) => fs.readFileSync(filePath),
    requestPassphrase: (fileName) => requestPassphraseFromWebview(panel, fileName),
    postMessage: (message) => {
      panel.webview.postMessage(message);
    },
  };
}

export function requestInputDialogFromWebview(
  panel: vscode.WebviewPanel,
  title: string,
  fields: InputDialogFieldDef[],
  options?: { icon?: string; description?: string; confirmLabel?: string; cancelLabel?: string }
): Promise<Record<string, string> | null> {
  return requestInputDialog(createQueuedWebviewSink(panel), title, fields, options);
}

export function requestPassphraseFromWebview(
  panel: vscode.WebviewPanel,
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean }
): Promise<string | null> {
  return requestPassphrase(createQueuedWebviewSink(panel), fileName, options);
}

function downloadBytesFromUrl(url: string, redirectsLeft = 3): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let parsed: URL;
    try { parsed = new URL(url); } catch { reject(new Error('Invalid URL')); return; }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      reject(new Error('Only http:// and https:// URLs are supported'));
      return;
    }

    const requester = parsed.protocol === 'https:' ? https : http;
    const req = requester.get(url, { timeout: 10_000 }, (res) => {
      if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        if (redirectsLeft <= 0) { reject(new Error('Too many redirects')); return; }
        const next = new URL(res.headers.location, url).toString();
        resolve(downloadBytesFromUrl(next, redirectsLeft - 1));
        return;
      }
      if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
        reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
        return;
      }
      const MAX_BYTES = 512 * 1024;
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BYTES) { req.destroy(); reject(new Error('Response too large (>512 KB)')); return; }
        chunks.push(chunk);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
  });
}

export function getOrCreatePanel(
  extensionUri: vscode.Uri,
  context: vscode.ExtensionContext
): vscode.WebviewPanel {
  if (currentPanel) {
    viewerQueue.reset();
    currentPanel.webview.html = buildHtml(currentPanel.webview, extensionUri, { title: 'X.509 Certificate Toolkit' });
    currentPanel.reveal(vscode.ViewColumn.Two, false);
    return currentPanel;
  }

  const panel = vscode.window.createWebviewPanel(
    'x509toolkit',
    'X.509 Certificate Toolkit',
    { viewColumn: vscode.ViewColumn.Two, preserveFocus: false },
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'dist', 'webview')],
      retainContextWhenHidden: true,
    }
  );

  viewerQueue.reset();
  panel.webview.html = buildHtml(panel.webview, extensionUri, { title: 'X.509 Certificate Toolkit' });
  extensionContext = context;

  panel.webview.onDidReceiveMessage(
    (msg: WebviewToExtMsg) => { handleWebviewMessage(panel, msg); },
    undefined,
    context.subscriptions
  );

  panel.onDidDispose(() => {
    currentPanel = undefined;
    viewerQueue.reset();
    pendingViewerCsrPem = undefined;
    pendingViewerCsrKeyPem = undefined;
  }, null, context.subscriptions);

  currentPanel = panel;
  return panel;
}

export function sendLoading(panel: vscode.WebviewPanel, status?: string): void {
  pendingViewerCsrPem = undefined;
  pendingViewerCsrKeyPem = undefined;
  const msg: ExtToWebviewMsg = status ? { type: 'loading', status } : { type: 'loading' };
  viewerQueue.post(panel, msg);
}

export function sendCertificates(
  panel: vscode.WebviewPanel,
  chain: CertificateData[],
  activeIndex = 0,
  tlsSource?: TlsConnectionInfo
): void {
  pendingViewerCsrPem = undefined;
  pendingViewerCsrKeyPem = undefined;
  const msg: ExtToWebviewMsg = tlsSource
    ? { type: 'certificate', chain, activeIndex, tlsSource }
    : { type: 'certificate', chain, activeIndex };
  viewerQueue.post(panel, msg);
}

export function sendCsr(panel: vscode.WebviewPanel, data: CsrData, keyPem?: string): void {
  pendingViewerCsrKeyPem = keyPem;
  pendingViewerCsrPem = data.raw;
  let csrData = data;
  if (keyPem) {
    const { algorithm, keySize, namedCurve } = data.publicKey;
    const algDesc = keySize ? `${algorithm}-${keySize}` : namedCurve ? `${algorithm} ${namedCurve}` : algorithm;
    csrData = { ...data, privateKeyDescription: keyPem.includes('ENCRYPTED') ? `${algDesc} (encrypted)` : algDesc };
  }
  const msg: ExtToWebviewMsg = { type: 'csr', data: csrData };
  viewerQueue.post(panel, msg);
}

export function sendError(panel: vscode.WebviewPanel, message: string): void {
  const msg: ExtToWebviewMsg = { type: 'error', message };
  viewerQueue.post(panel, msg);
}

// ============================================================
// Message dispatch
// ============================================================

export async function handleWebviewMessage(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg
): Promise<void> {
  if (msg.type === 'ready') {
    viewerQueue.ready = true;
    viewerQueue.flushPending(panel);
    return;
  }

  return routeViewerMessage(msg, {
    copyToClipboard: (message) => handleCopyToClipboard(panel, message),
    passphraseResponse: (message) => handlePassphraseResponse(panel, message),
    inputDialogResponse: (message) => handleInputDialogResponse(panel, message),
    downloadCaIssuer: (message) => handleDownloadCaIssuer(panel, message),
    openCaCertFile: (message) => handleOpenCaCertFile(panel, message),
    exportCert: (message) => handleExportCert(panel, message),
    exportPrivateKey: (message) => handleExportPrivateKey(panel, message),
    importPrivateKey: (message) => handleImportPrivateKey(panel, message),
    createP12: (message) => handleCreateP12(panel, message),
    signCsr: (message) => handleSignCsr(panel, message),
    savePrivateKey: (message) => handleSavePrivateKey(panel, message),
    saveCsrFile: (message) => handleSaveCsrFile(panel, message),
    saveBothFiles: (message) => handleSaveBothFiles(panel, message),
    openConvertHub: (message) => handleOpenConvertHub(panel, message),
  });
}

// ============================================================
// Message handlers
// ============================================================

async function handleCopyToClipboard(
  _panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'copyToClipboard' }
): Promise<void> {
  vscode.env.clipboard.writeText(msg.value);
  vscode.window.showInformationMessage('Copied to clipboard.');
}

async function handlePassphraseResponse(
  _panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'passphraseResponse' }
): Promise<void> {
  resolvePassphraseRequest(msg.requestId, msg.passphrase);
}

async function handleInputDialogResponse(
  _panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'inputDialogResponse' }
): Promise<void> {
  resolveInputDialogRequest(msg.requestId, msg.values);
}

async function handleDownloadCaIssuer(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'downloadCaIssuer' }
): Promise<void> {
  const { url } = msg;
  downloadBytesFromUrl(url)
    .then(buf => parseCertificate(buf))
    .then(cert => {
      const reply: ExtToWebviewMsg = { type: 'caIssuerCert', cert, url };
      panel.webview.postMessage(reply);
    })
    .catch((err: unknown) => {
      const reply: ExtToWebviewMsg = {
        type: 'caIssuerError',
        url,
        message: (err as Error).message ?? String(err),
      };
      panel.webview.postMessage(reply);
    });
}

async function handleOpenCaCertFile(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'openCaCertFile' }
): Promise<void> {
  const { topCertPem } = msg;
  const uris = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: 'Open CA Certificate',
    title: 'Open CA / Issuer Certificate',
    filters: {
      'Certificate Files': ['pem', 'crt', 'cer', 'der'],
      'All Files': ['*'],
    },
  });
  if (!uris?.[0]) return;
  const filePath = uris[0].fsPath;
  const fileUrl = `file://${filePath.replace(/\\/g, '/')}`;
  const sendFileErr = (message: string) =>
    panel.webview.postMessage({ type: 'caIssuerError', url: fileUrl, message } as ExtToWebviewMsg);
  try {
    const buf = fs.readFileSync(filePath);
    const asText = buf.toString('utf8').trim();
    const certs = asText.includes('-----BEGIN CERTIFICATE-----')
      ? await parsePEMChain(asText)
      : [await parseCertificate(buf)];

    const topX509 = new X509Certificate(topCertPem);
    const failure = validateIssuerChain(
      topX509,
      certs.map(cert => new X509Certificate(cert.raw))
    );
    if (failure) {
      sendFileErr(formatIssuerChainFailure(failure));
      return;
    }

    // All valid — send each cert to the webview
    certs.forEach((cert, idx) => {
      const url = certs.length > 1 ? `${fileUrl}#${idx}` : fileUrl;
      const reply: ExtToWebviewMsg = { type: 'caIssuerCert', cert, url };
      panel.webview.postMessage(reply);
    });
  } catch (err) {
    sendFileErr((err as Error).message ?? String(err));
  }
}

async function handleExportCert(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'exportCert' }
): Promise<void> {
  return exportCertificate(createViewerFileActionHost(panel), msg);
}

async function handleExportPrivateKey(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'exportPrivateKey' }
): Promise<void> {
  return exportPrivateKey(createViewerFileActionHost(panel), msg);
}

async function handleImportPrivateKey(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'importPrivateKey' }
): Promise<void> {
  return importPrivateKey(createKeyImportHost(panel), msg, loadAndValidatePrivateKey);
}

async function handleCreateP12(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'createP12' }
): Promise<void> {
  const { certPems, suggestedName, keyPem } = msg;

  // Step 1 — use embedded key if present, otherwise optionally pick a file
  let keyBuf: Buffer | undefined;
  if (keyPem) {
    keyBuf = Buffer.from(keyPem, 'utf8');
  } else {
    const keyUris = await vscode.window.showOpenDialog({
      canSelectMany: false,
      openLabel: 'Include Key',
      title: 'Select Private Key File — Cancel to create a certs-only P12',
      filters: {
        'Private Key': ['pem', 'key', 'der', 'pk8'],
        'All Files': ['*'],
      },
    });
    if (keyUris?.[0]) {
      const rawKeyBuf = fs.readFileSync(keyUris[0].fsPath);
      const keyFileName = keyUris[0].fsPath.split(/[\\/]/).pop() ?? 'private key';

      // Detect whether the key file is encrypted
      const isEncryptedPem = isEncryptedKey(rawKeyBuf);

      if (isEncryptedPem) {
        const keyPassphrase = await requestPassphraseFromWebview(panel, keyFileName, {
          title: 'Private Key Passphrase',
          description: `${keyFileName} is encrypted. Enter its passphrase to decrypt it.`,
          buttonLabel: 'Decrypt',
        });
        if (keyPassphrase === null) return;
        try {
          const nodeKey = crypto.createPrivateKey({ key: rawKeyBuf, passphrase: keyPassphrase });
          keyBuf = Buffer.from(nodeKey.export({ type: 'pkcs8', format: 'pem' }) as string, 'utf8');
        } catch (e) {
          vscode.window.showErrorMessage(`Failed to decrypt private key: ${(e as Error).message}`);
          return;
        }
      } else {
        keyBuf = rawKeyBuf;
      }
    }
  }

  // Step 2 — ask for password only when a key is included
  let password = '';
  if (keyBuf) {
    const baseName = suggestedName.split(/[\\/]/).pop() ?? suggestedName;
    const input = await requestPassphraseFromWebview(panel, baseName, {
      title: 'Set P12 Password',
      description: `Enter a password to protect the private key in ${baseName}. Leave empty for no password.`,
      buttonLabel: 'Set Password',
      requireConfirm: true,
    });
    if (input === null) return;
    password = input;
  }

  // Step 3 — build the P12
  let p12Buf: Buffer;
  try {
    p12Buf = createP12Buffer(certPems, password, keyBuf);
  } catch (err) {
    vscode.window.showErrorMessage(`Failed to create P12: ${(err as Error).message}`);
    return;
  }

  // Step 4 — save dialog
  const saveUri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file(suggestedName),
    filters: { 'PKCS#12 / PFX': ['p12', 'pfx'] },
    saveLabel: 'Save P12',
    title: 'Save P12 File',
  });
  if (!saveUri) return;
  fs.writeFileSync(saveUri.fsPath, p12Buf);
  const note = keyBuf ? ' (with private key)' : ' (certificates only)';
  vscode.window.showInformationMessage(`P12 saved to ${saveUri.fsPath}${note}`);
}

async function handleSignCsr(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'signCsr' }
): Promise<void> {
  const { csrPem } = msg;

  // Step 1 — CA certificate
  const caCertUris = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: 'Select CA Certificate',
    title: 'Sign CSR — Select CA Certificate (PEM or DER)',
    filters: { 'Certificate Files': ['pem', 'crt', 'cer', 'der'], 'All Files': ['*'] },
  });
  if (!caCertUris?.[0]) return;
  let caCertPem: string;
  try {
    const caBuf = fs.readFileSync(caCertUris[0].fsPath);
    const caCert = await parseCertificate(caBuf);
    caCertPem = caCert.raw;
  } catch (e) {
    vscode.window.showErrorMessage(`Failed to load CA certificate: ${(e as Error).message}`);
    return;
  }

  // Step 2 — CA private key (with passphrase support)
  const caKeyUris = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: 'Select CA Private Key',
    title: 'Sign CSR — Select CA Private Key (PEM)',
    filters: { 'Private Key': ['pem', 'key', 'der', 'pk8'], 'All Files': ['*'] },
  });
  if (!caKeyUris?.[0]) return;
  let caKeyPem: string;
  try {
    const raw = fs.readFileSync(caKeyUris[0].fsPath);
    const isPem = raw.toString('utf8').trimStart().startsWith('-----');
    const keyInput = isPem ? raw.toString('utf8') : raw;
    let nodeKey: ReturnType<typeof crypto.createPrivateKey>;
    try {
      nodeKey = crypto.createPrivateKey(keyInput);
    } catch (firstErr) {
      const errMsg = (firstErr as Error).message ?? '';
      if (/passphrase|encrypted|bad decrypt|EVP_|PKCS/i.test(errMsg)) {
        const result = await requestInputDialogFromWebview(
          panel,
          'CA Private Key Passphrase',
          [{
            id: 'passphrase',
            label: 'Passphrase',
            type: 'password',
            placeholder: 'Enter passphrase',
            required: true,
            hint: 'This private key is encrypted. Enter its passphrase.',
          }],
          { icon: '🔑', confirmLabel: 'Unlock' },
        );
        if (result === null) return;
        const passphrase = result['passphrase'];
        nodeKey = crypto.createPrivateKey({ key: keyInput as string | Buffer, passphrase });
      } else {
        throw firstErr;
      }
    }
    caKeyPem = nodeKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  } catch (e) {
    vscode.window.showErrorMessage(`Failed to load CA key: ${(e as Error).message}`);
    return;
  }

  // Step 3 — Requester's private key file
  const reqKeyUris = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel: 'Select Private Key',
    title: 'Sign CSR — Select Your Private Key (saved when the CSR was created)',
    filters: { 'Private Key': ['pem', 'key', 'der', 'pk8'], 'All Files': ['*'] },
  });
  if (!reqKeyUris?.[0]) return;
  let requesterKeyPem: string;
  try {
    const raw = fs.readFileSync(reqKeyUris[0].fsPath);
    const keyText = raw.toString('utf8').trim();
    let nodeKey: ReturnType<typeof crypto.createPrivateKey>;
    try {
      nodeKey = crypto.createPrivateKey(keyText);
    } catch (firstErr) {
      const errMsg = (firstErr as Error).message ?? '';
      if (/passphrase|encrypted|bad decrypt|EVP_|PKCS/i.test(errMsg)) {
        const fileName = reqKeyUris[0].fsPath.split(/[\\/]/).pop() ?? 'private key';
        const passphrase = await requestPassphraseFromWebview(panel, fileName, {
          title: 'Private Key Passphrase',
          description: `${fileName} is password-protected. Enter its passphrase.`,
          buttonLabel: 'Unlock',
        });
        if (passphrase === null) return;
        nodeKey = crypto.createPrivateKey({ key: keyText, passphrase });
      } else {
        throw firstErr;
      }
    }
    requesterKeyPem = nodeKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  } catch (e) {
    vscode.window.showErrorMessage(`Failed to load private key: ${(e as Error).message}`);
    return;
  }

  // Step 4 — Validity days
  const validityResult = await requestInputDialogFromWebview(
    panel,
    'Certificate Validity',
    [{ id: 'days', label: 'Validity (days)', type: 'number', value: '365', min: '1', max: '36500', step: 1, required: true, hint: 'How many days the signed certificate should be valid.' }],
    { icon: '📅', confirmLabel: 'Continue' }
  );
  if (!validityResult) return;
  const daysStr = validityResult.days;

  // Step 5 — P12 password
  const p12Passphrase = await requestPassphraseFromWebview(
    panel,
    'signed-certificate.p12',
    {
      title: 'Set P12 Password',
      description: 'Enter a password to protect the private key in the output P12 file. Leave empty for no password.',
      buttonLabel: 'Set Password',
      requireConfirm: true,
    },
  );
  if (p12Passphrase === null) return;

  // Sign
  let p12Buf: Buffer;
  try {
    p12Buf = await signCsr(csrPem, caCertPem, caKeyPem, requesterKeyPem, parseInt(daysStr, 10), p12Passphrase);
  } catch (e) {
    vscode.window.showErrorMessage(`Signing failed: ${(e as Error).message}`);
    return;
  }

  // Save
  const saveUri = await vscode.window.showSaveDialog({
    defaultUri: vscode.Uri.file('signed-certificate.p12'),
    filters: { 'PKCS#12 / PFX': ['p12', 'pfx'] },
    saveLabel: 'Save Signed Certificate',
    title: 'Save Signed Certificate as P12',
  });
  if (!saveUri) return;
  fs.writeFileSync(saveUri.fsPath, p12Buf);
  vscode.window.showInformationMessage(`Signed certificate saved to ${saveUri.fsPath}`);

  // Show in viewer
  const { parseP12 } = await import('@x509-toolkit/core');
  sendLoading(panel);
  try {
    const certs = await parseP12(p12Buf, p12Passphrase);
    sendCertificates(panel, certs, 0);
  } catch { /* file is saved; viewer just stays on loading */ }
}

async function handleSavePrivateKey(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'savePrivateKey' }
): Promise<void> {
  void msg;
  return savePrivateKeyFromMemory(createViewerFileActionHost(panel), pendingViewerCsrKeyPem);
}

async function handleSaveCsrFile(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'saveCsrFile' }
): Promise<void> {
  void msg;
  return saveCsrFromMemory(createViewerFileActionHost(panel), pendingViewerCsrPem);
}

async function handleSaveBothFiles(
  panel: vscode.WebviewPanel,
  msg: WebviewToExtMsg & { type: 'saveBothFiles' }
): Promise<void> {
  return saveCsrAndPrivateKey(
    createViewerFileActionHost(panel),
    pendingViewerCsrPem,
    pendingViewerCsrKeyPem,
    msg.suggestedName
  );
}

async function handleOpenConvertHub(
  _panel: vscode.WebviewPanel,
  _msg: WebviewToExtMsg & { type: 'openConvertHub' }
): Promise<void> {
  openConvertPanel(extensionContext);
}

// HTML builder is now shared via webviewPanelUtils.ts
