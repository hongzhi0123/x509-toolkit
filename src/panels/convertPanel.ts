import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { parseCertificate, parsePEMChain } from '../parsers/certificateParser';
import { parseP12, createP12Buffer } from '../parsers/p12Parser';
import type { ConvertToExtMsg, ExtToConvertMsg } from '../types/types';

let convertPanelRef: vscode.WebviewPanel | undefined;

export function openConvertPanel(context: vscode.ExtensionContext): void {
  if (convertPanelRef) {
    convertPanelRef.reveal(vscode.ViewColumn.Two, false);
    return;
  }

  // Stores picked file paths keyed by slotId — scoped to this panel instance
  const pickedFiles = new Map<string, string>();

  const panel = vscode.window.createWebviewPanel(
    'x509ConvertHub',
    'Format Conversion Hub',
    { viewColumn: vscode.ViewColumn.Two, preserveFocus: false },
    {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, 'dist', 'webview')],
      retainContextWhenHidden: true,
    },
  );

  panel.webview.html = buildConvertHtml(panel.webview, context.extensionUri);

  panel.webview.onDidReceiveMessage(
    async (msg: ConvertToExtMsg) => {
      switch (msg.type) {

        case 'convertReady':
          break;

        case 'convertPickFile': {
          const uris = await vscode.window.showOpenDialog({
            canSelectMany: false,
            filters: { ...msg.filters, 'All Files': ['*'] },
          });
          if (!uris?.[0]) break;
          pickedFiles.set(msg.slotId, uris[0].fsPath);
          post(panel, {
            type: 'convertFileSelected',
            slotId: msg.slotId,
            fileName: path.basename(uris[0].fsPath),
          });
          break;
        }

        case 'convertPickFiles': {
          const uris = await vscode.window.showOpenDialog({
            canSelectMany: true,
            filters: { ...msg.filters, 'All Files': ['*'] },
          });
          if (!uris?.length) break;
          uris.forEach((uri, i) => pickedFiles.set(`${msg.slotId}_${i}`, uri.fsPath));
          post(panel, {
            type: 'convertFileSelected',
            slotId: msg.slotId,
            fileName: `${uris.length} file(s) selected`,
            fileCount: uris.length,
          });
          break;
        }

        case 'convertExecuteExtractP12': {
          const p12Path = pickedFiles.get('p12Input');
          if (!p12Path) {
            post(panel, { type: 'convertError', message: 'No P12 file selected.' });
            break;
          }
          let certs: Awaited<ReturnType<typeof parseP12>>;
          try {
            const buf = fs.readFileSync(p12Path);
            certs = await parseP12(buf, msg.passphrase);
          } catch (e) {
            post(panel, { type: 'convertError', message: `Failed to open P12: ${(e as Error).message}` });
            break;
          }

          let savedCount = 0;
          try {
            if (msg.outputMode === 'bundle') {
              const bundlePem = certs.map(c => c.raw).join('\n');
              const baseName = path.basename(p12Path, path.extname(p12Path));
              const uri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`${baseName}-certs.pem`),
                filters: { 'PEM Certificate Chain': ['pem', 'crt'], 'All Files': ['*'] },
                saveLabel: 'Save Certificate Bundle',
                title: 'Save All Certificates as PEM Bundle',
              });
              if (uri) { fs.writeFileSync(uri.fsPath, bundlePem, 'utf8'); savedCount++; }
            } else {
              for (let i = 0; i < certs.length; i++) {
                const cn = certs[i].subject.commonName ?? `cert-${i}`;
                const safeName = cn.replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 48);
                const uri = await vscode.window.showSaveDialog({
                  defaultUri: vscode.Uri.file(`${safeName}.pem`),
                  filters: { 'PEM Certificate': ['pem', 'crt', 'cer'], 'All Files': ['*'] },
                  saveLabel: `Save Certificate ${i + 1} of ${certs.length}`,
                  title: `Save Certificate ${i + 1} of ${certs.length}`,
                });
                if (uri) { fs.writeFileSync(uri.fsPath, certs[i].raw, 'utf8'); savedCount++; }
              }
            }

            if (msg.includeKey) {
              const keyPem = certs[0]?.privateKey?.pem;
              if (keyPem) {
                const baseName = path.basename(p12Path, path.extname(p12Path));
                const uri = await vscode.window.showSaveDialog({
                  defaultUri: vscode.Uri.file(`${baseName}.key`),
                  filters: { 'Private Key': ['key', 'pem'], 'All Files': ['*'] },
                  saveLabel: 'Save Private Key',
                  title: 'Save Extracted Private Key',
                });
                if (uri) { fs.writeFileSync(uri.fsPath, keyPem, 'utf8'); savedCount++; }
              }
            }

            post(panel, { type: 'convertResult', message: `Saved ${savedCount} file(s) successfully.` });
          } catch (e) {
            post(panel, { type: 'convertError', message: (e as Error).message });
          }
          break;
        }

        case 'convertExecuteBuildP12': {
          const certPath = pickedFiles.get('certInput');
          if (!certPath) {
            post(panel, { type: 'convertError', message: 'No certificate file selected.' });
            break;
          }

          let certPems: string[];
          try {
            const buf = fs.readFileSync(certPath);
            const text = buf.toString('utf8').trim();
            const parsed = text.includes('-----BEGIN CERTIFICATE-----')
              ? await parsePEMChain(text)
              : [await parseCertificate(buf)];
            certPems = parsed.map(c => c.raw);
          } catch (e) {
            post(panel, { type: 'convertError', message: `Failed to read certificate: ${(e as Error).message}` });
            break;
          }

          let keyBuf: Buffer | undefined;
          if (msg.includeKey) {
            const keyPath = pickedFiles.get('keyInput');
            if (keyPath) {
              try {
                keyBuf = fs.readFileSync(keyPath);
              } catch (e) {
                post(panel, { type: 'convertError', message: `Failed to read key file: ${(e as Error).message}` });
                break;
              }
            }
          }

          let p12Buf: Buffer;
          try {
            p12Buf = createP12Buffer(certPems, msg.passphrase, keyBuf);
          } catch (e) {
            post(panel, { type: 'convertError', message: `Failed to build P12: ${(e as Error).message}` });
            break;
          }

          const p12BaseName = path.basename(certPath, path.extname(certPath));
          const saveUri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file(`${p12BaseName}.p12`),
            filters: { 'PKCS#12': ['p12', 'pfx'], 'All Files': ['*'] },
            saveLabel: 'Save P12',
            title: 'Save P12 / PFX File',
          });
          if (!saveUri) break;
          fs.writeFileSync(saveUri.fsPath, p12Buf);
          const note = keyBuf ? ' (with private key)' : ' (certificates only)';
          post(panel, { type: 'convertResult', message: `P12 saved${note}.` });
          break;
        }

        case 'convertExecuteConvertFormat': {
          const slotId = msg.assetType === 'cert' ? 'certInput' : 'keyInput';
          const inputPath = pickedFiles.get(slotId);
          if (!inputPath) {
            post(panel, { type: 'convertError', message: 'No input file selected.' });
            break;
          }
          try {
            const buf = fs.readFileSync(inputPath);
            const baseName = path.basename(inputPath, path.extname(inputPath));

            if (msg.direction === 'pem-to-der') {
              let derBuf: Buffer;
              let filterLabel: string;
              if (msg.assetType === 'cert') {
                const b64 = buf.toString('utf8')
                  .replace(/-----BEGIN CERTIFICATE-----/g, '')
                  .replace(/-----END CERTIFICATE-----/g, '')
                  .replace(/\s+/g, '');
                derBuf = Buffer.from(b64, 'base64');
                filterLabel = 'DER Certificate';
              } else {
                const nodeKey = crypto.createPrivateKey(buf.toString('utf8').trim());
                derBuf = nodeKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
                filterLabel = 'DER Private Key';
              }
              const saveUri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`${baseName}.der`),
                filters: { [filterLabel]: ['der'], 'All Files': ['*'] },
                saveLabel: 'Save DER File',
                title: 'Save as DER',
              });
              if (!saveUri) break;
              fs.writeFileSync(saveUri.fsPath, derBuf);
              post(panel, { type: 'convertResult', message: 'DER file saved.' });

            } else {
              // DER → PEM
              let pemStr: string;
              if (msg.assetType === 'cert') {
                const cert = await parseCertificate(buf);
                pemStr = cert.raw;
              } else {
                let nodeKey: ReturnType<typeof crypto.createPrivateKey> | undefined;
                for (const type of ['pkcs8', 'pkcs1', 'sec1'] as const) {
                  try {
                    nodeKey = crypto.createPrivateKey({ key: buf, format: 'der', type });
                    break;
                  } catch { /* try next format */ }
                }
                if (!nodeKey) {
                  post(panel, { type: 'convertError', message: 'Could not parse DER key — unsupported format.' });
                  break;
                }
                pemStr = nodeKey.export({ type: 'pkcs8', format: 'pem' }) as string;
              }
              const saveUri = await vscode.window.showSaveDialog({
                defaultUri: vscode.Uri.file(`${baseName}.pem`),
                filters: { 'PEM File': ['pem', 'crt', 'key'], 'All Files': ['*'] },
                saveLabel: 'Save PEM File',
                title: 'Save as PEM',
              });
              if (!saveUri) break;
              fs.writeFileSync(saveUri.fsPath, pemStr, 'utf8');
              post(panel, { type: 'convertResult', message: 'PEM file saved.' });
            }
          } catch (e) {
            post(panel, { type: 'convertError', message: (e as Error).message });
          }
          break;
        }

        case 'convertExecuteBundleChain': {
          const { orderedSlotIds } = msg;
          if (!orderedSlotIds.length) {
            post(panel, { type: 'convertError', message: 'No certificate files selected.' });
            break;
          }
          const allPems: string[] = [];
          for (const slotId of orderedSlotIds) {
            const filePath = pickedFiles.get(slotId);
            if (!filePath) continue;
            try {
              const buf = fs.readFileSync(filePath);
              const text = buf.toString('utf8').trim();
              const certs = text.includes('-----BEGIN CERTIFICATE-----')
                ? await parsePEMChain(text)
                : [await parseCertificate(buf)];
              allPems.push(...certs.map(c => c.raw));
            } catch (e) {
              post(panel, { type: 'convertError', message: `Failed to read ${path.basename(filePath)}: ${(e as Error).message}` });
              return;
            }
          }
          const bundlePem = allPems.join('\n');
          const saveUri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file('bundle.pem'),
            filters: { 'PEM Bundle': ['pem', 'crt'], 'All Files': ['*'] },
            saveLabel: 'Save Bundle',
            title: 'Save Certificate Chain Bundle',
          });
          if (!saveUri) break;
          fs.writeFileSync(saveUri.fsPath, bundlePem, 'utf8');
          post(panel, {
            type: 'convertResult',
            message: `Bundle saved with ${allPems.length} certificate(s).`,
          });
          break;
        }
      }
    },
    undefined,
    context.subscriptions,
  );

  panel.onDidDispose(() => {
    convertPanelRef = undefined;
    pickedFiles.clear();
  }, null, context.subscriptions);

  convertPanelRef = panel;
}

function post(panel: vscode.WebviewPanel, msg: ExtToConvertMsg): void {
  panel.webview.postMessage(msg);
}

// ─── HTML builder ─────────────────────────────────────────────────────────────

function getNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length: 32 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function buildConvertHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
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
  <title>Format Conversion Hub</title>
</head>
<body>
  <div id="app" data-view="convertHub"></div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}
