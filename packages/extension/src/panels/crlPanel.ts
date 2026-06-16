import * as vscode from 'vscode';
import * as fs from 'fs';
import { parseCrl, parsePemCrlChain } from '@x509-toolkit/core';
import type { CrlData, CrlViewerToExtMsg, ExtToCrlViewerMsg } from '@x509-toolkit/core';

let crlPanelRef: vscode.WebviewPanel | undefined;
let crlPanelReady = false;
let pendingCrlMessages: ExtToCrlViewerMsg[] = [];

function post(panel: vscode.WebviewPanel, msg: ExtToCrlViewerMsg): void {
  if (!crlPanelReady) {
    pendingCrlMessages.push(msg);
    return;
  }
  panel.webview.postMessage(msg);
}

function flushPending(panel: vscode.WebviewPanel): void {
  if (!crlPanelReady || pendingCrlMessages.length === 0) return;
  const queued = pendingCrlMessages;
  pendingCrlMessages = [];
  queued.forEach(message => panel.webview.postMessage(message));
}

function getNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function buildHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
  const scriptUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'dist', 'webview', 'main.js'),
  );
  const styleUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'dist', 'webview', 'styles.css'),
  );
  const nonce = getNonce();
  return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta property="csp-nonce" nonce="${nonce}">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none';
                 style-src ${webview.cspSource} 'unsafe-inline';
                 script-src 'nonce-${nonce}' ${webview.cspSource};">
  <link href="${styleUri}" rel="stylesheet">
  <title>CRL Viewer</title>
</head>
<body>
  <div id="app" data-view="crlViewer"></div>
  <script type="module" nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}

function getOrCreateCrlPanel(context: vscode.ExtensionContext): vscode.WebviewPanel {
  if (crlPanelRef) {
    crlPanelReady = false;
    pendingCrlMessages = [];
    crlPanelRef.webview.html = buildHtml(crlPanelRef.webview, context.extensionUri);
    crlPanelRef.reveal(vscode.ViewColumn.Two, false);
    return crlPanelRef;
  }

  const panel = vscode.window.createWebviewPanel(
    'x509CrlViewer',
    'CRL Viewer',
    { viewColumn: vscode.ViewColumn.Two, preserveFocus: false },
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'dist', 'webview')],
      retainContextWhenHidden: true,
    },
  );

  crlPanelReady = false;
  pendingCrlMessages = [];
  panel.webview.html = buildHtml(panel.webview, context.extensionUri);

  panel.webview.onDidReceiveMessage(
    (msg: CrlViewerToExtMsg) => {
      switch (msg.type) {
        case 'crlViewerReady':
          crlPanelReady = true;
          flushPending(panel);
          break;
        case 'copyToClipboard':
          vscode.env.clipboard.writeText(msg.value);
          vscode.window.showInformationMessage('Copied to clipboard.');
          break;
      }
    },
    undefined,
    context.subscriptions,
  );

  panel.onDidDispose(() => {
    crlPanelRef = undefined;
    crlPanelReady = false;
    pendingCrlMessages = [];
  });

  crlPanelRef = panel;
  return panel;
}

/**
 * Open and parse a CRL file, then display it in the CRL Viewer panel.
 */
export function openCrlFile(
  context: vscode.ExtensionContext,
  uri?: vscode.Uri,
): () => Promise<void> {
  return async () => {
    let filePath: string;

    if (uri) {
      filePath = uri.fsPath;
    } else {
      const uris = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Open CRL File',
        filters: {
          'CRL Files': ['crl', 'pem'],
          'All Files': ['*'],
        },
      });
      if (!uris || uris.length === 0) return;
      filePath = uris[0].fsPath;
    }

    const fileName = filePath.split(/[\\/]/).pop() ?? 'file';
    const panel = getOrCreateCrlPanel(context);
    panel.title = `CRL — ${fileName}`;
    post(panel, { type: 'crlLoading' });

    try {
      const buf = fs.readFileSync(filePath);
      const ext = filePath.toLowerCase().split('.').pop() ?? '';

      let crls: CrlData[];
      if (ext === 'pem' || buf.toString('ascii', 0, 32).includes('-----BEGIN')) {
        crls = parsePemCrlChain(buf);
      } else {
        crls = [parseCrl(buf)];
      }

      if (crls.length === 0) {
        post(panel, { type: 'crlError', message: 'No CRL entries found in file.' });
        return;
      }

      // Send the first CRL (or all, for multi-CRL PEM — currently send first only)
      post(panel, { type: 'crlData', crl: crls[0] });
    } catch (err: unknown) {
      post(panel, { type: 'crlError', message: (err as Error).message ?? String(err) });
    }
  };
}
