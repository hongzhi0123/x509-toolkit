import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { parseKeyFile, isEncryptedKey } from '@x509-toolkit/core';
import type { ExtToKeyViewerMsg, KeyViewerToExtMsg, StandaloneKeyData } from '@x509-toolkit/core';
import { requestPassphrase, resolvePassphraseRequest } from '../utils/requestBridgeUtils';
import { buildHtml, createMessageQueue } from '../utils/webviewPanelUtils';

let keyPanelRef: vscode.WebviewPanel | undefined;
const keyQueue = createMessageQueue<ExtToKeyViewerMsg>();

// Held for the lifetime of the open panel — cleared on dispose
let heldNodeKey: crypto.KeyObject | undefined;

function requestPassphraseFromKeyPanel(
  panel: vscode.WebviewPanel,
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
): Promise<string | null> {
  return requestPassphrase(
    { postMessage: (msg) => keyQueue.post(panel, msg as ExtToKeyViewerMsg) },
    fileName,
    options,
  );
}

function getOrCreateKeyPanel(context: vscode.ExtensionContext): vscode.WebviewPanel {
  if (keyPanelRef) {
    keyQueue.reset();
    keyPanelRef.webview.html = buildHtml(keyPanelRef.webview, context.extensionUri, { title: 'Key Viewer', dataView: 'keyViewer' });
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

  keyQueue.reset();
  panel.webview.html = buildHtml(panel.webview, context.extensionUri, { title: 'Key Viewer', dataView: 'keyViewer' });

  panel.webview.onDidReceiveMessage(
    async (msg: KeyViewerToExtMsg) => {
      switch (msg.type) {

        case 'keyViewerReady':
          keyQueue.ready = true;
          keyQueue.flushPending(panel);
          break;

        case 'copyToClipboard':
          vscode.env.clipboard.writeText(msg.value);
          vscode.window.showInformationMessage('Copied to clipboard.');
          break;

        case 'passphraseResponse':
          resolvePassphraseRequest(msg.requestId, msg.passphrase);
          break;

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
    keyQueue.reset();
    heldNodeKey = undefined;
  }, null, context.subscriptions);

  keyPanelRef = panel;
  return panel;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Open the key viewer with a pre-loaded buffer.
 * Handles encrypted key passphrase prompts in the webview.
 */
export async function openKeyFromBuffer(
  context: vscode.ExtensionContext,
  buf: Buffer,
  displayName: string,
): Promise<void> {
  const panel = getOrCreateKeyPanel(context);
  keyQueue.post(panel, { type: 'keyLoading' });

  const encrypted = isEncryptedKey(buf);

  const tryParse = async (passphrase?: string): Promise<boolean> => {
    try {
      const { data, nodeKey } = parseKeyFile(buf, passphrase);
      heldNodeKey = nodeKey;
      keyQueue.post(panel, { type: 'keyData', key: data });
      return true;
    } catch {
      return false;
    }
  };

  if (encrypted) {
    const passphrase = await requestPassphraseFromKeyPanel(panel, displayName, {
      title: 'Key File Passphrase',
      description: `${displayName} is encrypted. Enter its passphrase.`,
      buttonLabel: 'Open',
    });
    if (passphrase === null) {
      keyQueue.post(panel, { type: 'keyError', message: 'Operation cancelled.' });
      return;
    }
    const ok = await tryParse(passphrase);
    if (!ok) {
      const pp2 = await requestPassphraseFromKeyPanel(panel, displayName, {
        title: 'Key File Passphrase',
        description: `Incorrect passphrase for ${displayName}. Try again.`,
        buttonLabel: 'Open',
      });
      if (pp2 === null) {
        keyQueue.post(panel, { type: 'keyError', message: 'Operation cancelled.' });
        return;
      }
      const ok2 = await tryParse(pp2);
      if (!ok2) {
        keyQueue.post(panel, { type: 'keyError', message: 'Incorrect passphrase or corrupted key file.' });
      }
    }
  } else {
    const ok = await tryParse();
    if (!ok) {
      keyQueue.post(panel, { type: 'keyError', message: 'Failed to parse key — not a recognised private or public key format.' });
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
  keyQueue.post(panel, { type: 'keyData', key: keyData });
}
