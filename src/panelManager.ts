import * as vscode from 'vscode';
import type { CertificateData, ExtToWebviewMsg, WebviewToExtMsg } from './types';

let currentPanel: vscode.WebviewPanel | undefined;

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
