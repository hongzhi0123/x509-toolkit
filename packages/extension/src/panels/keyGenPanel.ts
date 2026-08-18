import * as vscode from 'vscode';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { generateKeyPair } from '@x509-toolkit/core';
import { openKeyViewerWithKey } from './keyPanel';
import type { ExtToKeyGenMsg, InputDialogFieldDef, KeyGenToExtMsg } from '@x509-toolkit/core';
import { requestInputDialog, resolveInputDialogRequest } from '../utils/requestBridgeUtils';
import { buildHtml, createMessageQueue } from '../utils/webviewPanelUtils';

let keyGenPanelRef: vscode.WebviewPanel | undefined;
const keyGenQueue = createMessageQueue<ExtToKeyGenMsg>();

// Held for the lifetime of the open panel — cleared on dispose
let heldPrivKey: crypto.KeyObject | undefined;
let heldPrivKeyPem: string | undefined;
let heldPubKeyPem: string | undefined;

function requestInputDialogFromKeyGen(
  panel: vscode.WebviewPanel,
  title: string,
  fields: InputDialogFieldDef[],
  options?: { icon?: string; description?: string; confirmLabel?: string; cancelLabel?: string },
): Promise<Record<string, string> | null> {
  return requestInputDialog(
    { postMessage: (msg) => keyGenQueue.post(panel, msg as ExtToKeyGenMsg) },
    title,
    fields,
    options,
  );
}

export function openKeyGenPanel(context: vscode.ExtensionContext): () => void {
  return () => {
    if (keyGenPanelRef) {
      keyGenQueue.reset();
      keyGenPanelRef.webview.html = buildHtml(keyGenPanelRef.webview, context.extensionUri, { title: 'Key Generator', dataView: 'keyGen' });
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

    keyGenQueue.reset();
    panel.webview.html = buildHtml(panel.webview, context.extensionUri, { title: 'Key Generator', dataView: 'keyGen' });

    heldPrivKey = undefined;
    heldPrivKeyPem = undefined;
    heldPubKeyPem = undefined;

    panel.webview.onDidReceiveMessage(
      async (msg: KeyGenToExtMsg) => {
        switch (msg.type) {

          case 'keyGenReady':
            keyGenQueue.ready = true;
            keyGenQueue.flushPending(panel);
            break;

          case 'inputDialogResponse':
            resolveInputDialogRequest(msg.requestId, msg.values);
            break;

          case 'copyToClipboard':
            vscode.env.clipboard.writeText(msg.value);
            vscode.window.showInformationMessage('Copied to clipboard.');
            break;

          case 'keyGenGenerate': {
            keyGenQueue.post(panel, { type: 'keyGenGenerating' });
            try {
              const result = await generateKeyPair(msg.algorithm);
              heldPrivKey = result.nodeKey;
              heldPrivKeyPem = result.privateKeyPem;
              heldPubKeyPem = result.publicKeyPem;
              keyGenQueue.post(panel, { type: 'keyGenDone', key: result.data });
            } catch (e) {
              keyGenQueue.post(panel, { type: 'keyGenError', message: (e as Error).message });
            }
            break;
          }

          case 'keyGenSavePrivateKey': {
            if (!heldPrivKeyPem || !heldPrivKey) break;

            // Ask whether to encrypt
            const resp = await requestInputDialogFromKeyGen(
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
      keyGenQueue.reset();
      heldPrivKey = undefined;
      heldPrivKeyPem = undefined;
      heldPubKeyPem = undefined;
    }, null, context.subscriptions);

    keyGenPanelRef = panel;
  };
}
