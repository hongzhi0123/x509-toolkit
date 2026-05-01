import * as vscode from 'vscode';
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import { parseCertificate } from './certificateParser';
import { createP12Buffer, loadAndValidatePrivateKey } from './p12Parser';
import type { CertificateData, ExtToWebviewMsg, WebviewToExtMsg } from './types';

let currentPanel: vscode.WebviewPanel | undefined;

// ------------------------------------------------------------------
// Passphrase request bridge
// Maps requestId → resolve function of the awaiting Promise
// ------------------------------------------------------------------
const pendingPassphraseRequests = new Map<string, (passphrase: string | null) => void>();

export function requestPassphraseFromWebview(
  panel: vscode.WebviewPanel,
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean }
): Promise<string | null> {
  const requestId = `pp-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return new Promise<string | null>(resolve => {
    pendingPassphraseRequests.set(requestId, resolve);
    const msg: ExtToWebviewMsg = { type: 'requestPassphrase', requestId, fileName, ...options };
    panel.webview.postMessage(msg);
  });
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
    currentPanel.reveal(vscode.ViewColumn.Two, false);
    return currentPanel;
  }

  const panel = vscode.window.createWebviewPanel(
    'x509viewer',
    'X.509 Certificate Viewer',
    { viewColumn: vscode.ViewColumn.Two, preserveFocus: false },
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'dist', 'webview')],
      retainContextWhenHidden: true,
    }
  );

  panel.webview.html = buildHtml(panel.webview, extensionUri);

  panel.webview.onDidReceiveMessage(
    async (msg: WebviewToExtMsg) => {
      if (msg.type === 'copyToClipboard') {
        vscode.env.clipboard.writeText(msg.value);
        vscode.window.showInformationMessage('Copied to clipboard.');
      } else if (msg.type === 'passphraseResponse') {
        const resolve = pendingPassphraseRequests.get(msg.requestId);
        if (resolve) {
          pendingPassphraseRequests.delete(msg.requestId);
          resolve(msg.passphrase);
        }
      } else if (msg.type === 'downloadCaIssuer') {
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
      } else if (msg.type === 'exportCert') {
        const { pem, suggestedName } = msg;
        vscode.window.showSaveDialog({
          defaultUri: vscode.Uri.file(suggestedName),
          filters: {
            'PEM Certificate': ['pem', 'crt', 'cer'],
            'DER Certificate': ['der', 'cer'],
          },
          saveLabel: 'Export Certificate',
          title: 'Export Certificate',
        }).then(uri => {
          if (!uri) return;
          const ext = uri.fsPath.split('.').pop()?.toLowerCase() ?? 'pem';
          let data: Buffer;
          if (ext === 'der') {
            // Strip PEM headers and decode base64 to binary DER
            const b64 = pem
              .replace(/-----BEGIN CERTIFICATE-----/g, '')
              .replace(/-----END CERTIFICATE-----/g, '')
              .replace(/\s+/g, '');
            data = Buffer.from(b64, 'base64');
          } else {
            data = Buffer.from(pem, 'utf8');
          }
          fs.writeFileSync(uri.fsPath, data);
          vscode.window.showInformationMessage(`Certificate exported to ${uri.fsPath}`);
        });
      } else if (msg.type === 'importPrivateKey') {
        const { certIndex, spkiPem } = msg;
        const keyUris = await vscode.window.showOpenDialog({
          canSelectMany: false,
          openLabel: 'Import Private Key',
          title: 'Select Private Key File (PEM or DER)',
          filters: {
            'Private Key': ['pem', 'key', 'der', 'pk8'],
            'All Files': ['*'],
          },
        });
        if (!keyUris?.[0]) return; // user cancelled
        const keyBuf = fs.readFileSync(keyUris[0].fsPath);

        // Detect encrypted PEM upfront so we can ask for a passphrase before parsing
        const keyText = keyBuf.toString('utf8');
        const isEncryptedPem =
          keyText.includes('BEGIN ENCRYPTED PRIVATE KEY') ||
          /Proc-Type:\s*4,ENCRYPTED/i.test(keyText);

        let passphrase: string | undefined;
        if (isEncryptedPem) {
          const input = await requestPassphraseFromWebview(
            panel,
            keyUris[0].fsPath.split(/[\\/]/).pop() ?? 'private key'
          );
          if (input === null) return; // user cancelled
          passphrase = input;
        }

        const postKeyResult = async (pass: string | undefined) => {
          try {
            const keyInfo = loadAndValidatePrivateKey(keyBuf, spkiPem, pass);
            const reply: ExtToWebviewMsg = { type: 'privateKeyImported', certIndex, key: keyInfo };
            panel.webview.postMessage(reply);
            return true;
          } catch (err) {
            return err as Error;
          }
        };

        const result = await postKeyResult(passphrase);
        if (result === true) {
          // success — handled inside
        } else {
          // If we didn't ask for a passphrase yet and the error suggests the key
          // is encrypted (e.g. encrypted DER), give the user one chance to provide one
          const errMsg = result.message;
          if (!passphrase && /passphrase|bad decrypt|encrypt|unsupported|interrupt/i.test(errMsg)) {
            const input = await requestPassphraseFromWebview(
              panel,
              keyUris[0].fsPath.split(/[\\/]/).pop() ?? 'private key'
            );
            if (input === null) return; // user cancelled — no error shown
            const retry = await postKeyResult(input);
            if (retry !== true) {
              panel.webview.postMessage({
                type: 'privateKeyImportError', certIndex,
                message: (retry as Error).message,
              } as ExtToWebviewMsg);
            }
          } else {
            panel.webview.postMessage({
              type: 'privateKeyImportError', certIndex, message: errMsg,
            } as ExtToWebviewMsg);
          }
        }
      } else if (msg.type === 'createP12') {
        const { certPems, suggestedName, keyPem } = msg;

        // Step 1 — use embedded key if present, otherwise optionally pick a file
        let keyBuf: Buffer | undefined;
        if (keyPem) {
          // Private key already available from the opened certificate — skip the file picker
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
          keyBuf = keyUris?.[0] ? fs.readFileSync(keyUris[0].fsPath) : undefined;
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
          if (input === null) return; // user cancelled
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
    },
    undefined,
    context.subscriptions
  );

  panel.onDidDispose(() => { currentPanel = undefined; }, null, context.subscriptions);

  currentPanel = panel;
  return panel;
}

export function sendLoading(panel: vscode.WebviewPanel): void {
  const msg: ExtToWebviewMsg = { type: 'loading' };
  panel.webview.postMessage(msg);
}

export function sendCertificates(
  panel: vscode.WebviewPanel,
  chain: CertificateData[],
  activeIndex = 0
): void {
  const msg: ExtToWebviewMsg = { type: 'certificate', chain, activeIndex };
  panel.webview.postMessage(msg);
}

export function sendError(panel: vscode.WebviewPanel, message: string): void {
  const msg: ExtToWebviewMsg = { type: 'error', message };
  panel.webview.postMessage(msg);
}

// ------------------------------------------------------------------
// HTML builder
// ------------------------------------------------------------------

function getNonce(): string {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

function buildHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
  const scriptUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'dist', 'webview', 'main.js')
  );
  const styleUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'dist', 'webview', 'styles.css')
  );
  const nonce = getNonce();

  return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none';
                 style-src ${webview.cspSource} 'unsafe-inline';
                 script-src 'nonce-${nonce}';">
  <link href="${styleUri}" rel="stylesheet">
  <title>X.509 Certificate Viewer</title>
</head>
<body>
  <div id="app"></div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}
