import * as vscode from 'vscode';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { parseCertificate } from './certificateParser';
import { parseP12, generateCertificate } from './p12Parser';
import { getOrCreatePanel, sendLoading, sendCertificates } from './panelManager';
import type { CertCreateParams, CreateCertToExtMsg, ExtToCreateCertMsg } from './types';

let createCertPanelRef: vscode.WebviewPanel | undefined;

// Held for the lifetime of the open panel
let pendingCaCertPem: string | undefined;
let pendingCaKeyPem: string | undefined;

export function openCreateCertPanel(
  extensionUri: vscode.Uri,
  context: vscode.ExtensionContext,
): void {
  if (createCertPanelRef) {
    createCertPanelRef.reveal(vscode.ViewColumn.One, false);
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    'x509CreateCert',
    'Create Certificate',
    { viewColumn: vscode.ViewColumn.One, preserveFocus: false },
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'dist', 'webview')],
      retainContextWhenHidden: true,
    },
  );

  panel.webview.html = buildHtml(panel.webview, extensionUri);

  pendingCaCertPem = undefined;
  pendingCaKeyPem  = undefined;

  panel.webview.onDidReceiveMessage(
    async (msg: CreateCertToExtMsg) => {
      switch (msg.type) {

        case 'ready':
          break;

        case 'pickCaCert': {
          const uris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: 'Select CA Certificate',
            title: 'Select CA Certificate (PEM or DER)',
            filters: {
              'Certificate Files': ['pem', 'crt', 'cer', 'der'],
              'All Files': ['*'],
            },
          });
          if (!uris?.[0]) break;
          try {
            const buf = fs.readFileSync(uris[0].fsPath);
            const cert = await parseCertificate(buf);
            pendingCaCertPem = cert.raw;
            post(panel, { type: 'caCertLoaded', subject: cert.subject.raw });
          } catch (e) {
            post(panel, { type: 'error', message: `Failed to load CA cert: ${(e as Error).message}` });
          }
          break;
        }

        case 'pickCaKey': {
          const uris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: 'Select CA Private Key',
            title: 'Select CA Private Key (PEM)',
            filters: {
              'Private Key': ['pem', 'key', 'der', 'pk8'],
              'All Files': ['*'],
            },
          });
          if (!uris?.[0]) break;
          try {
            const raw = fs.readFileSync(uris[0].fsPath);
            const isPem = raw.toString('utf8').trimStart().startsWith('-----');
            const keyInput = isPem ? raw.toString('utf8') : raw;

            let nodeKey: ReturnType<typeof crypto.createPrivateKey>;
            try {
              // First attempt: no passphrase
              nodeKey = crypto.createPrivateKey(keyInput);
            } catch (firstErr) {
              const msg = (firstErr as Error).message ?? '';
              // If the error looks like an encryption/passphrase error, prompt the user
              if (/passphrase|encrypted|bad decrypt|EVP_|PKCS/i.test(msg)) {
                const passphrase = await vscode.window.showInputBox({
                  title: 'CA Private Key Passphrase',
                  prompt: 'This private key is encrypted. Enter its passphrase.',
                  password: true,
                  ignoreFocusOut: true,
                });
                if (passphrase === undefined) break;  // user cancelled
                nodeKey = crypto.createPrivateKey({ key: keyInput as string | Buffer, passphrase });
              } else {
                throw firstErr;
              }
            }

            const details = nodeKey.asymmetricKeyDetails as Record<string, unknown> ?? {};
            const keyType = nodeKey.asymmetricKeyType ?? 'unknown';
            const desc =
              details.modulusLength ? `RSA-${details.modulusLength as number}` :
              details.namedCurve   ? `EC ${details.namedCurve as string}` :
              keyType.toUpperCase();

            // Store the key as unencrypted PKCS#8 PEM so generateCertificate can load it
            pendingCaKeyPem = nodeKey.export({ type: 'pkcs8', format: 'pem' }) as string;
            post(panel, { type: 'caKeyLoaded', description: desc });
          } catch (e) {
            post(panel, { type: 'error', message: `Failed to load CA key: ${(e as Error).message}` });
          }
          break;
        }

        case 'generate': {
          const params: CertCreateParams = msg.params;
          post(panel, { type: 'generating' });
          let p12Buf: Buffer;
          try {
            p12Buf = await generateCertificate(
              params,
              params.signingMode === 'ca-signed' ? pendingCaCertPem : undefined,
              params.signingMode === 'ca-signed' ? pendingCaKeyPem  : undefined,
            );
          } catch (e) {
            post(panel, { type: 'error', message: (e as Error).message ?? String(e) });
            break;
          }

          // Ask where to save
          const safeName = (params.cn || 'certificate')
            .replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 64);
          const saveUri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(`${safeName}.p12`),
            filters: { 'PKCS#12': ['p12', 'pfx'], 'All Files': ['*'] },
            saveLabel: 'Save Certificate',
            title: 'Save Generated Certificate as P12',
          });
          if (!saveUri) {
            post(panel, { type: 'done' });
            break;
          }
          fs.writeFileSync(saveUri.fsPath, p12Buf);
          vscode.window.showInformationMessage(`Certificate saved to ${saveUri.fsPath}`);

          // Close form, show cert in viewer
          panel.dispose();
          const viewerPanel = getOrCreatePanel(extensionUri, context);
          sendLoading(viewerPanel);
          try {
            const certs = await parseP12(p12Buf, params.password);
            sendCertificates(viewerPanel, certs, 0);
          } catch {
            // viewer will show the error; the file is saved successfully already
          }
          break;
        }

        case 'cancel':
          panel.dispose();
          break;
      }
    },
    undefined,
    context.subscriptions,
  );

  panel.onDidDispose(() => {
    createCertPanelRef  = undefined;
    pendingCaCertPem    = undefined;
    pendingCaKeyPem     = undefined;
  }, null, context.subscriptions);

  createCertPanelRef = panel;
}

function post(panel: vscode.WebviewPanel, msg: ExtToCreateCertMsg): void {
  panel.webview.postMessage(msg);
}

// ─── HTML builder ─────────────────────────────────────────────────────────────

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
  <title>Create Certificate</title>
</head>
<body>
  <div id="app" data-view="createCert"></div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}
