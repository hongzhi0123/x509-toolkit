import * as vscode from 'vscode';
import * as fs from 'fs';
import { parseCrl, parsePemCrlChain } from '@x509-toolkit/core';
import type { CrlData, CrlViewerToExtMsg, ExtToCrlViewerMsg } from '@x509-toolkit/core';
import { buildHtml, createMessageQueue } from '../utils/webviewPanelUtils';

let crlPanelRef: vscode.WebviewPanel | undefined;
const crlQueue = createMessageQueue<ExtToCrlViewerMsg>();

function getOrCreateCrlPanel(context: vscode.ExtensionContext): vscode.WebviewPanel {
  if (crlPanelRef) {
    crlQueue.reset();
    crlPanelRef.webview.html = buildHtml(crlPanelRef.webview, context.extensionUri, { title: 'CRL Viewer', dataView: 'crlViewer' });
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

  crlQueue.reset();
  panel.webview.html = buildHtml(panel.webview, context.extensionUri, { title: 'CRL Viewer', dataView: 'crlViewer' });

  panel.webview.onDidReceiveMessage(
    (msg: CrlViewerToExtMsg) => {
      switch (msg.type) {
        case 'crlViewerReady':
          crlQueue.ready = true;
          crlQueue.flushPending(panel);
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
    crlQueue.reset();
  });

  crlPanelRef = panel;
  return panel;
}

async function openCrlFromBufferInternal(
  context: vscode.ExtensionContext,
  buf: Buffer,
  displayName: string,
  extHint?: string,
): Promise<void> {
  const panel = getOrCreateCrlPanel(context);
  panel.title = `CRL — ${displayName}`;
  crlQueue.post(panel, { type: 'crlLoading' });

  try {
    const ext = extHint ?? '';

    let crls: CrlData[];
    if (ext === 'pem' || buf.toString('ascii', 0, 64).includes('-----BEGIN')) {
      crls = parsePemCrlChain(buf);
    } else {
      crls = [parseCrl(buf)];
    }

    if (crls.length === 0) {
      crlQueue.post(panel, { type: 'crlError', message: 'No CRL entries found in file.' });
      return;
    }

    // Send the first CRL (or all, for multi-CRL PEM — currently send first only)
    crlQueue.post(panel, { type: 'crlData', crl: crls[0] });
  } catch (err: unknown) {
    crlQueue.post(panel, { type: 'crlError', message: (err as Error).message ?? String(err) });
  }
}

export async function openCrlFromBuffer(
  context: vscode.ExtensionContext,
  buf: Buffer,
  displayName: string,
  extHint?: string,
): Promise<void> {
  await openCrlFromBufferInternal(context, buf, displayName, extHint);
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

    try {
      const buf = fs.readFileSync(filePath);
      const ext = filePath.toLowerCase().split('.').pop() ?? '';
      await openCrlFromBufferInternal(context, buf, fileName, ext);
    } catch (err: unknown) {
      const panel = getOrCreateCrlPanel(context);
      panel.title = `CRL — ${fileName}`;
      crlQueue.post(panel, { type: 'crlError', message: (err as Error).message ?? String(err) });
    }
  };
}
