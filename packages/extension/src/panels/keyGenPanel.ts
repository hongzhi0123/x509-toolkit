import * as vscode from 'vscode';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { generateKeyPair } from '@x509-toolkit/core';
import { openKeyViewerWithKey } from './keyPanel';
import type { ExtToKeyGenMsg, KeyGenToExtMsg, InputDialogFieldDef } from '@x509-toolkit/core';

let keyGenPanelRef: vscode.WebviewPanel | undefined;
let keyGenPanelReady = false;
let pendingKeyGenMessages: ExtToKeyGenMsg[] = [];

// Held for the lifetime of the open panel — cleared on dispose
let heldPrivKey: crypto.KeyObject | undefined;
let heldPrivKeyPem: string | undefined;
let heldPubKeyPem: string | undefined;

// Input dialog request bridge (used to prompt for passphrase on save)
const pendingInputDialogRequests = new Map<string, (values: Record<string, string> | null) => void>();

function requestInputDialog(
  panel: vscode.WebviewPanel,
  title: string,
  fields: InputDialogFieldDef[],
  options?: { icon?: string; description?: string; confirmLabel?: string; cancelLabel?: string },
): Promise<Record<string, string> | null> {
  const requestId = `kgen-idlg-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  return new Promise(resolve => {
    pendingInputDialogRequests.set(requestId, resolve);
    const msg: ExtToKeyGenMsg = { type: 'requestInputDialog', requestId, title, fields, ...options };
    post(panel, msg);
  });
}

function post(panel: vscode.WebviewPanel, msg: ExtToKeyGenMsg): void {
  if (!keyGenPanelReady) {
    pendingKeyGenMessages.push(msg);
    return;
  }
  panel.webview.postMessage(msg);
}

function flushPending(panel: vscode.WebviewPanel): void {
  if (!keyGenPanelReady || pendingKeyGenMessages.length === 0) return;
  const queued = pendingKeyGenMessages;
  pendingKeyGenMessages = [];
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
  <title>Key Generator</title>
</head>
<body>
  <div id="app" data-view="keyGen"></div>
  <script type="module" nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}

export function openKeyGenPanel(context: vscode.ExtensionContext): () => void {
  return () => {
    if (keyGenPanelRef) {
      keyGenPanelReady = false;
      pendingKeyGenMessages = [];
      keyGenPanelRef.webview.html = buildHtml(keyGenPanelRef.webview, context.extensionUri);
      keyGenPanelRef.reveal(vscode.ViewColumn.One, false);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'x509KeyGenerator',
      'Key Generator',
      { viewColumn: vscode.ViewColumn.One, preserveFocus: false },
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'dist', 'webview')],
        retainContextWhenHidden: true,
      },
    );

    keyGenPanelReady = false;
    pendingKeyGenMessages = [];
    panel.webview.html = buildHtml(panel.webview, context.extensionUri);

    heldPrivKey = undefined;
    heldPrivKeyPem = undefined;
    heldPubKeyPem = undefined;

    panel.webview.onDidReceiveMessage(
      async (msg: KeyGenToExtMsg) => {
        switch (msg.type) {

          case 'keyGenReady':
            keyGenPanelReady = true;
            flushPending(panel);
            break;

          case 'inputDialogResponse': {
            const resolve = pendingInputDialogRequests.get(msg.requestId);
            if (resolve) {
              pendingInputDialogRequests.delete(msg.requestId);
              resolve(msg.values);
            }
            break;
          }

          case 'copyToClipboard':
            vscode.env.clipboard.writeText(msg.value);
            vscode.window.showInformationMessage('Copied to clipboard.');
            break;

          case 'keyGenGenerate': {
            post(panel, { type: 'keyGenGenerating' });
            try {
              const result = await generateKeyPair(msg.algorithm);
              heldPrivKey = result.nodeKey;
              heldPrivKeyPem = result.privateKeyPem;
              heldPubKeyPem = result.publicKeyPem;
              post(panel, { type: 'keyGenDone', key: result.data });
            } catch (e) {
              post(panel, { type: 'keyGenError', message: (e as Error).message });
            }
            break;
          }

          case 'keyGenSavePrivateKey': {
            if (!heldPrivKeyPem || !heldPrivKey) break;

            // Ask whether to encrypt
            const resp = await requestInputDialog(
              panel,
              'Save Private Key',
              [
                {
                  id: 'passphrase',
                  label: 'Passphrase (leave empty to save unencrypted)',
                  type: 'password',
                  placeholder: 'Optional passphrase',
                  hint: 'If set, the key will be exported as an encrypted PKCS#8 PEM file.',
                },
                {
                  id: 'confirm',
                  label: 'Confirm passphrase',
                  type: 'password',
                  placeholder: 'Repeat passphrase',
                },
              ],
              { icon: '🔑', confirmLabel: 'Save', cancelLabel: 'Cancel' },
            );
            if (!resp) break;

            const { passphrase, confirm } = resp;
            if (passphrase !== confirm) {
              vscode.window.showErrorMessage('Passphrases do not match.');
              break;
            }

            let keyData: Buffer;
            if (passphrase) {
              const enc = heldPrivKey.export({
                type: 'pkcs8',
                format: 'pem',
                cipher: 'aes-256-cbc',
                passphrase,
              }) as string;
              keyData = Buffer.from(enc, 'utf8');
            } else {
              keyData = Buffer.from(heldPrivKeyPem, 'utf8');
            }

            const uri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file('private.key'),
              filters: { 'Private Key': ['key', 'pem'], 'All Files': ['*'] },
              saveLabel: 'Save',
              title: 'Save Private Key',
            });
            if (!uri) break;
            fs.writeFileSync(uri.fsPath, keyData);
            vscode.window.showInformationMessage(`Private key saved.`);
            break;
          }

          case 'keyGenSavePublicKey': {
            if (!heldPubKeyPem) break;
            const uri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file('public.pem'),
              filters: { 'Public Key': ['pem', 'pub'], 'All Files': ['*'] },
              saveLabel: 'Save',
              title: 'Save Public Key (SPKI PEM)',
            });
            if (!uri) break;
            fs.writeFileSync(uri.fsPath, Buffer.from(heldPubKeyPem, 'utf8'));
            vscode.window.showInformationMessage(`Public key saved.`);
            break;
          }

          case 'keyGenViewKey': {
            if (!heldPrivKey || !heldPrivKeyPem) break;
            // Parse current key data for the viewer
            const { data } = await import('@x509-toolkit/core').then(m =>
              Promise.resolve(m.parseKeyFile(Buffer.from(heldPrivKeyPem!, 'utf8'))),
            );
            openKeyViewerWithKey(context, data, heldPrivKey);
            break;
          }
        }
      },
      undefined,
      context.subscriptions,
    );

    panel.onDidDispose(() => {
      keyGenPanelRef = undefined;
      keyGenPanelReady = false;
      pendingKeyGenMessages = [];
      heldPrivKey = undefined;
      heldPrivKeyPem = undefined;
      heldPubKeyPem = undefined;
      pendingInputDialogRequests.clear();
    }, null, context.subscriptions);

    keyGenPanelRef = panel;
  };
}
