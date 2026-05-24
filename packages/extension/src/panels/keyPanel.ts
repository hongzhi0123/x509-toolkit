import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { parseKeyFile, isEncryptedKey } from '@x509-toolkit/core';
import type { ExtToKeyViewerMsg, KeyViewerToExtMsg, StandaloneKeyData } from '@x509-toolkit/core';

let keyPanelRef: vscode.WebviewPanel | undefined;

// Held for the lifetime of the open panel — cleared on dispose
let heldNodeKey: crypto.KeyObject | undefined;

// Passphrase request bridge
const pendingPassphraseRequests = new Map<string, (passphrase: string | null) => void>();

function requestPassphraseFromKeyPanel(
  panel: vscode.WebviewPanel,
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
): Promise<string | null> {
  const requestId = `kv-pp-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return new Promise(resolve => {
    pendingPassphraseRequests.set(requestId, resolve);
    const msg: ExtToKeyViewerMsg = { type: 'requestPassphrase', requestId, fileName, ...options };
    panel.webview.postMessage(msg);
  });
}

function post(panel: vscode.WebviewPanel, msg: ExtToKeyViewerMsg): void {
  panel.webview.postMessage(msg);
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
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none';
                 style-src ${webview.cspSource} 'unsafe-inline';
                 script-src 'nonce-${nonce}';">
  <link href="${styleUri}" rel="stylesheet">
  <title>Key Viewer</title>
</head>
<body>
  <div id="app" data-view="keyViewer"></div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}

function getOrCreateKeyPanel(context: vscode.ExtensionContext): vscode.WebviewPanel {
  if (keyPanelRef) {
    keyPanelRef.reveal(vscode.ViewColumn.Two, false);
    return keyPanelRef;
  }

  const panel = vscode.window.createWebviewPanel(
    'x509KeyViewer',
    'Key Viewer',
    { viewColumn: vscode.ViewColumn.Two, preserveFocus: false },
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'dist', 'webview')],
      retainContextWhenHidden: true,
    },
  );

  panel.webview.html = buildHtml(panel.webview, context.extensionUri);

  panel.webview.onDidReceiveMessage(
    async (msg: KeyViewerToExtMsg) => {
      switch (msg.type) {

        case 'keyViewerReady':
          break;

        case 'copyToClipboard':
          vscode.env.clipboard.writeText(msg.value);
          vscode.window.showInformationMessage('Copied to clipboard.');
          break;

        case 'passphraseResponse': {
          const resolve = pendingPassphraseRequests.get(msg.requestId);
          if (resolve) {
            pendingPassphraseRequests.delete(msg.requestId);
            resolve(msg.passphrase);
          }
          break;
        }

        case 'exportPrivateKey': {
          if (!heldNodeKey || heldNodeKey.type !== 'private') break;
          const { format, encrypt, suggestedName } = msg;

          let passphrase: string | undefined;
          if (encrypt) {
            const pp = await requestPassphraseFromKeyPanel(panel, suggestedName, {
              title: 'Encrypt Private Key',
              description: 'Enter a passphrase to protect the exported key. Leave empty for no encryption.',
              buttonLabel: 'Export',
              requireConfirm: true,
            });
            if (pp === null) break;
            passphrase = pp || undefined;
          }

          try {
            let data: Buffer;
            const isText = format.endsWith('-pem');
            switch (format) {
              case 'pkcs8-pem':
                data = Buffer.from(
                  heldNodeKey.export(
                    passphrase
                      ? { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
                      : { type: 'pkcs8', format: 'pem' },
                  ) as string,
                  'utf8',
                );
                break;
              case 'pkcs8-der':
                data = heldNodeKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
                break;
              case 'pkcs1-pem':
                data = Buffer.from(heldNodeKey.export({ type: 'pkcs1', format: 'pem' }) as string, 'utf8');
                break;
              case 'pkcs1-der':
                data = heldNodeKey.export({ type: 'pkcs1', format: 'der' }) as Buffer;
                break;
              case 'sec1-pem':
                data = Buffer.from(heldNodeKey.export({ type: 'sec1', format: 'pem' }) as string, 'utf8');
                break;
              case 'sec1-der':
                data = heldNodeKey.export({ type: 'sec1', format: 'der' }) as Buffer;
                break;
              default:
                vscode.window.showErrorMessage('Unknown export format.');
                return;
            }

            const ext = isText ? 'pem' : 'der';
            const uri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file(`${suggestedName}.${ext}`),
              filters: isText
                ? { 'Private Key': ['pem', 'key'], 'All Files': ['*'] }
                : { 'DER Key': ['der', 'key'], 'All Files': ['*'] },
              saveLabel: 'Export Key',
              title: 'Save Private Key',
            });
            if (!uri) break;
            fs.writeFileSync(uri.fsPath, data);
            vscode.window.showInformationMessage(`Key saved to ${path.basename(uri.fsPath)}`);
          } catch (e) {
            vscode.window.showErrorMessage(`Export failed: ${(e as Error).message}`);
          }
          break;
        }

        case 'exportPublicKey': {
          if (!heldNodeKey) break;
          const { format, suggestedName } = msg;
          try {
            const pubKey = heldNodeKey.type === 'public'
              ? heldNodeKey
              : crypto.createPublicKey(heldNodeKey);
            const isText = format === 'spki-pem';
            const data = isText
              ? Buffer.from(pubKey.export({ type: 'spki', format: 'pem' }) as string, 'utf8')
              : (pubKey.export({ type: 'spki', format: 'der' }) as Buffer);

            const ext = isText ? 'pem' : 'der';
            const uri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file(`${suggestedName}.${ext}`),
              filters: isText
                ? { 'Public Key': ['pem', 'pub'], 'All Files': ['*'] }
                : { 'DER Public Key': ['der', 'pub'], 'All Files': ['*'] },
              saveLabel: 'Export Public Key',
              title: 'Save Public Key',
            });
            if (!uri) break;
            fs.writeFileSync(uri.fsPath, data);
            vscode.window.showInformationMessage(`Public key saved to ${path.basename(uri.fsPath)}`);
          } catch (e) {
            vscode.window.showErrorMessage(`Export failed: ${(e as Error).message}`);
          }
          break;
        }
      }
    },
    undefined,
    context.subscriptions,
  );

  panel.onDidDispose(() => {
    keyPanelRef = undefined;
    heldNodeKey = undefined;
    pendingPassphraseRequests.clear();
  }, null, context.subscriptions);

  keyPanelRef = panel;
  return panel;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Open the key viewer, prompting for a file if `uri` is not supplied.
 * Handles encrypted key passphrase prompts in the webview.
 */
export async function openKeyFile(
  context: vscode.ExtensionContext,
  uri?: vscode.Uri,
): Promise<void> {
  let filePath: string;

  if (uri) {
    filePath = uri.fsPath;
  } else {
    const uris = await vscode.window.showOpenDialog({
      canSelectMany: false,
      openLabel: 'Open Key File',
      title: 'Open Key File (PEM or DER)',
      filters: {
        'Key Files': ['pem', 'key', 'der', 'pk8', 'p8', 'pub'],
        'All Files': ['*'],
      },
    });
    if (!uris?.[0]) return;
    filePath = uris[0].fsPath;
  }

  const fileName = path.basename(filePath);
  const panel = getOrCreateKeyPanel(context);
  post(panel, { type: 'keyLoading' });

  let buf: Buffer;
  try {
    buf = fs.readFileSync(filePath);
  } catch (e) {
    post(panel, { type: 'keyError', message: `Failed to read file: ${(e as Error).message}` });
    return;
  }

  const encrypted = isEncryptedKey(buf);

  const tryParse = async (passphrase?: string): Promise<boolean> => {
    try {
      const { data, nodeKey } = parseKeyFile(buf, passphrase);
      heldNodeKey = nodeKey;
      post(panel, { type: 'keyData', key: data });
      return true;
    } catch {
      return false;
    }
  };

  if (encrypted) {
    const passphrase = await requestPassphraseFromKeyPanel(panel, fileName, {
      title: 'Key File Passphrase',
      description: `${fileName} is encrypted. Enter its passphrase.`,
      buttonLabel: 'Open',
    });
    if (passphrase === null) {
      post(panel, { type: 'keyError', message: 'Operation cancelled.' });
      return;
    }
    const ok = await tryParse(passphrase);
    if (!ok) {
      const pp2 = await requestPassphraseFromKeyPanel(panel, fileName, {
        title: 'Key File Passphrase',
        description: `Incorrect passphrase for ${fileName}. Try again.`,
        buttonLabel: 'Open',
      });
      if (pp2 === null) {
        post(panel, { type: 'keyError', message: 'Operation cancelled.' });
        return;
      }
      const ok2 = await tryParse(pp2);
      if (!ok2) {
        post(panel, { type: 'keyError', message: 'Incorrect passphrase or corrupted key file.' });
      }
    }
  } else {
    const ok = await tryParse();
    if (!ok) {
      post(panel, { type: 'keyError', message: 'Failed to parse key file — not a recognised private or public key format.' });
    }
  }
}

/**
 * Open the key viewer with a pre-parsed key (e.g. from the key generator panel).
 * The caller provides both the StandaloneKeyData and the underlying crypto.KeyObject.
 */
export function openKeyViewerWithKey(
  context: vscode.ExtensionContext,
  keyData: StandaloneKeyData,
  nodeKey: crypto.KeyObject,
): void {
  const panel = getOrCreateKeyPanel(context);
  heldNodeKey = nodeKey;
  post(panel, { type: 'keyData', key: keyData });
}
