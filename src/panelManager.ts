import * as vscode from 'vscode';
import * as https from 'https';
import * as http from 'http';
import { parseCertificate } from './certificateParser';
import type { CertificateData, ExtToWebviewMsg, WebviewToExtMsg } from './types';

let currentPanel: vscode.WebviewPanel | undefined;

// ------------------------------------------------------------------
// CA Issuer download helper
// ------------------------------------------------------------------

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
    (msg: WebviewToExtMsg) => {
      if (msg.type === 'copyToClipboard') {
        vscode.env.clipboard.writeText(msg.value);
        vscode.window.showInformationMessage('Copied to clipboard.');
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
          require('fs').writeFileSync(uri.fsPath, data);
          vscode.window.showInformationMessage(`Certificate exported to ${uri.fsPath}`);
        });
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
