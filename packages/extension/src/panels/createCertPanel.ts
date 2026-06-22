import * as vscode from 'vscode';
import * as fs from 'fs';
import * as crypto from 'crypto';
import { parseCertificate, parseCsr, parseP12, generateCertificate, generateCsr } from '@x509-toolkit/core';
import { getOrCreatePanel, sendLoading, sendCertificates, sendCsr } from './mainViewerPanel';
import type { CertCreateParams, CreateCertToExtMsg, ExtToCreateCertMsg, InputDialogFieldDef } from '@x509-toolkit/core';
import { requestInputDialog, resolveInputDialogRequest } from '../utils/requestBridgeUtils';
import { tryLoadPrivateKey } from '../utils/keyImportUtils';
import { buildHtml, createMessageQueue } from '../utils/webviewPanelUtils';

let createCertPanelRef: vscode.WebviewPanel | undefined;
const createCertQueue = createMessageQueue<ExtToCreateCertMsg>();

function requestInputDialogFromCreateCertPanel(
  panel: vscode.WebviewPanel,
  title: string,
  fields: InputDialogFieldDef[],
  options?: { icon?: string; description?: string; confirmLabel?: string; cancelLabel?: string }
): Promise<Record<string, string> | null> {
  return requestInputDialog(
    { postMessage: (msg) => createCertQueue.post(panel, msg as ExtToCreateCertMsg) },
    title,
    fields,
    options,
  );
}

// Held for the lifetime of the open panel
let pendingCaCertPem: string | undefined;
let pendingCaKeyPem: string | undefined;
let pendingCsrPem: string | undefined;
let pendingCsrKeyPem: string | undefined;

export function openCreateCertPanel(
  context: vscode.ExtensionContext
): () => void {
  return () => {
    var extensionUri: vscode.Uri = context.extensionUri;

    if (createCertPanelRef) {
      createCertQueue.reset();
      createCertPanelRef.webview.html = buildHtml(createCertPanelRef.webview, extensionUri, { title: 'Create Certificate', dataView: 'createCert' });
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

    createCertQueue.reset();
    panel.webview.html = buildHtml(panel.webview, extensionUri, { title: 'Create Certificate', dataView: 'createCert' });

    pendingCaCertPem = undefined;
    pendingCaKeyPem = undefined;

    panel.webview.onDidReceiveMessage(
      async (msg: CreateCertToExtMsg) => {
        switch (msg.type) {

          case 'ready':
            createCertQueue.ready = true;
            createCertQueue.flushPending(panel);
            break;

          case 'inputDialogResponse':
            resolveInputDialogRequest(msg.requestId, msg.values);
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
              createCertQueue.post(panel, { type: 'caCertLoaded', subject: cert.subject.raw });
            } catch (e) {
              createCertQueue.post(panel, { type: 'error', message: `Failed to load CA cert: ${(e as Error).message}` });
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

              const nodeKey = await tryLoadPrivateKey(keyInput, async () => {
                const result = await requestInputDialogFromCreateCertPanel(
                  panel,
                  'CA Private Key Passphrase',
                  [{
                    id: 'passphrase',
                    label: 'Passphrase',
                    type: 'password',
                    placeholder: 'Enter passphrase',
                    required: true,
                    hint: 'This private key is encrypted. Enter its passphrase.',
                  }],
                  { icon: '🔑', confirmLabel: 'Unlock' },
                );
                return result?.['passphrase'] ?? null;
              });
              if (!nodeKey) break;  // user cancelled

              const details = nodeKey.asymmetricKeyDetails as Record<string, unknown> ?? {};
              const keyType = nodeKey.asymmetricKeyType ?? 'unknown';
              const desc =
                details.modulusLength ? `RSA-${details.modulusLength as number}` :
                  details.namedCurve ? `EC ${details.namedCurve as string}` :
                    keyType.toUpperCase();

              // Store the key as unencrypted PKCS#8 PEM so generateCertificate can load it
              pendingCaKeyPem = nodeKey.export({ type: 'pkcs8', format: 'pem' }) as string;
              createCertQueue.post(panel, { type: 'caKeyLoaded', description: desc });
            } catch (e) {
              createCertQueue.post(panel, { type: 'error', message: `Failed to load CA key: ${(e as Error).message}` });
            }
            break;
          }

          case 'generate': {
            const params: CertCreateParams = msg.params;
            createCertQueue.post(panel, { type: 'generating' });
            let p12Buf: Buffer;
            try {
              p12Buf = await generateCertificate(
                params,
                params.signingMode === 'ca-signed' ? pendingCaCertPem : undefined,
                params.signingMode === 'ca-signed' ? pendingCaKeyPem : undefined,
              );
            } catch (e) {
              createCertQueue.post(panel, { type: 'error', message: (e as Error).message ?? String(e) });
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
              createCertQueue.post(panel, { type: 'done' });
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

          case 'generateCsr': {
            const { params, keyPassword } = msg;
            createCertQueue.post(panel, { type: 'generating' });
            try {
              const { csrPem, privateKeyPem } = await generateCsr(params);
              // Optionally encrypt the private key with the user-supplied password
              if (keyPassword) {
                const nodeKey = crypto.createPrivateKey(privateKeyPem);
                const encPem = nodeKey.export({
                  type: 'pkcs8', format: 'pem',
                  cipher: 'aes-256-cbc', passphrase: keyPassword,
                }) as string;
                pendingCsrKeyPem = encPem;
              } else {
                pendingCsrKeyPem = privateKeyPem;
              }
              pendingCsrPem = csrPem;

              // Show the CSR in the viewer panel (with key stored in memory) and close this panel
              try {
                const viewerPanel = getOrCreatePanel(extensionUri, context);
                const csrData = await parseCsr(csrPem);
                sendCsr(viewerPanel, csrData, pendingCsrKeyPem);
              } catch { /* non-fatal: viewer key/CSR still work */ }
              panel.dispose();
            } catch (e) {
              createCertQueue.post(panel, { type: 'error', message: (e as Error).message ?? String(e) });
            }
            break;
          }

          case 'saveCsrFile': {
            if (!pendingCsrPem) break;
            const csrUri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file('request.csr'),
              filters: { 'Certificate Signing Request': ['csr', 'req', 'pem'], 'All Files': ['*'] },
              saveLabel: 'Save CSR',
              title: 'Save Certificate Signing Request',
            });
            if (!csrUri) break;
            fs.writeFileSync(csrUri.fsPath, pendingCsrPem, 'utf8');
            vscode.window.showInformationMessage(`CSR saved to ${csrUri.fsPath}`);
            break;
          }

          case 'savePrivateKey': {
            if (!pendingCsrKeyPem) break;
            const keyUri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file('private.key'),
              filters: { 'Private Key': ['key', 'pem'], 'All Files': ['*'] },
              saveLabel: 'Save Private Key',
              title: 'Save Private Key',
            });
            if (!keyUri) break;
            fs.writeFileSync(keyUri.fsPath, pendingCsrKeyPem, 'utf8');
            vscode.window.showInformationMessage(`Private key saved to ${keyUri.fsPath}`);
            break;
          }
        }
      },
      undefined,
      context.subscriptions,
    );

    panel.onDidDispose(() => {
      createCertPanelRef = undefined;
      createCertQueue.reset();
      pendingCaCertPem = undefined;
      pendingCaKeyPem = undefined;
      pendingCsrPem = undefined;
      pendingCsrKeyPem = undefined;
    }, null, context.subscriptions);

    createCertPanelRef = panel;
  }
}
