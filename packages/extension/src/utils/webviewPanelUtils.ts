import * as vscode from 'vscode';

export function getNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

export function buildHtml(webview: vscode.Webview, extensionUri: vscode.Uri, options: {
  title: string;
  dataView?: string;
}): string {
  const scriptUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'dist', 'webview', 'main.js'),
  );
  const styleUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, 'dist', 'webview', 'styles.css'),
  );
  const nonce = getNonce();
  const dataViewAttr = options.dataView ? ` data-view="${options.dataView}"` : '';

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
  <title>${options.title}</title>
</head>
<body>
  <div id="app"${dataViewAttr}></div>
  <script type="module" nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}

export function createMessageQueue<T extends { type: string }>() {
  let ready = false;
  let pending: T[] = [];

  return {
    get ready() { return ready; },
    set ready(v: boolean) { ready = v; },
    post(panel: vscode.WebviewPanel, msg: T): void {
      if (!ready) {
        pending.push(msg);
        return;
      }
      panel.webview.postMessage(msg);
    },
    flushPending(panel: vscode.WebviewPanel): void {
      if (!ready || pending.length === 0) return;
      const queued = pending;
      pending = [];
      queued.forEach(m => panel.webview.postMessage(m));
    },
    reset(): void {
      ready = false;
      pending = [];
    },
  };
}
