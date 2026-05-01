import * as vscode from 'vscode';
import * as fs from 'fs';
import { parseCertificate, parsePEMChain } from './certificateParser';
import { parseP12, createSelfSignedP12 } from './p12Parser';
import { openCreateCertPanel } from './createCertPanel';
import {
  getOrCreatePanel,
  sendLoading,
  sendCertificates,
  sendError,
  requestPassphraseFromWebview,
} from './panelManager';

async function openP12File(
  filePath: string,
  panel: ReturnType<typeof getOrCreatePanel>,
): Promise<void> {
  const fileName = filePath.split(/[\\/]/).pop() ?? 'file.p12';
  const password = await requestPassphraseFromWebview(panel, fileName, {
    title: 'P12 / PFX Password',
    description: `Enter the password for ${fileName}. Leave empty if the file has no password.`,
    buttonLabel: 'Open',
  });

  // null means the user cancelled
  if (password === null) {
    sendError(panel, 'Operation cancelled.');
    return;
  }

  const raw = fs.readFileSync(filePath);
  const certs = await parseP12(raw, password);
  sendCertificates(panel, certs, 0);
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('x509toolkit.showFromSelection', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('No active editor found.');
        return;
      }

      const selection = editor.selection;
      const selectedText = editor.document.getText(
        selection.isEmpty ? undefined : selection
      );

      if (!selectedText.trim()) {
        vscode.window.showWarningMessage(
          'No text selected. Please select PEM certificate text and try again.'
        );
        return;
      }

      const panel = getOrCreatePanel(context.extensionUri, context);
      sendLoading(panel);

      try {
        const chain = await parsePEMChain(selectedText);
        sendCertificates(panel, chain, 0);
      } catch (err: unknown) {
        sendError(panel, (err as Error).message ?? String(err));
      }
    })
  );

  // Command: open certificate file (PEM, DER, P12/PFX)
  context.subscriptions.push(
    vscode.commands.registerCommand('x509toolkit.openFile', async () => {
      const uris = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Open Certificate',
        filters: {
          'Certificate Files': ['pem', 'crt', 'cer', 'der', 'p7b', 'p7c', 'p12', 'pfx'],
          'All Files': ['*'],
        },
      });

      if (!uris || uris.length === 0) return;

      const filePath = uris[0].fsPath;
      const ext = filePath.toLowerCase().split('.').pop();

      const panel = getOrCreatePanel(context.extensionUri, context);
      sendLoading(panel);

      try {
        if (ext === 'p12' || ext === 'pfx') {
          await openP12File(filePath, panel);
          return;
        }

        const raw = fs.readFileSync(filePath);
        const asText = raw.toString('utf8');

        if (asText.includes('-----BEGIN CERTIFICATE-----')) {
          const chain = await parsePEMChain(asText);
          sendCertificates(panel, chain, 0);
        } else {
          const cert = await parseCertificate(raw);
          sendCertificates(panel, [cert], 0);
        }
      } catch (err: unknown) {
        sendError(panel, (err as Error).message ?? String(err));
      }
    })
  );

  // Command: open P12/PFX file explicitly
  context.subscriptions.push(
    vscode.commands.registerCommand('x509toolkit.openP12', async () => {
      const uris = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Open P12 / PFX',
        filters: {
          'PKCS#12 Files': ['p12', 'pfx'],
          'All Files': ['*'],
        },
      });

      if (!uris || uris.length === 0) return;

      const panel = getOrCreatePanel(context.extensionUri, context);
      sendLoading(panel);

      try {
        await openP12File(uris[0].fsPath, panel);
      } catch (err: unknown) {
        sendError(panel, (err as Error).message ?? String(err));
      }
    })
  );

  // Command: generate a sample self-signed P12
  context.subscriptions.push(
    vscode.commands.registerCommand('x509toolkit.createSelfSignedP12', async () => {
      const cn = await vscode.window.showInputBox({
        title: 'Create Self-Signed P12 — Common Name',
        prompt: 'Common Name (CN) for the certificate',
        value: 'Self-Signed',
        ignoreFocusOut: true,
        validateInput: v => v.trim() ? null : 'Common Name cannot be empty',
      });
      if (cn === undefined) return;

      const daysStr = await vscode.window.showInputBox({
        title: 'Create Self-Signed P12 — Validity',
        prompt: 'Validity period in days',
        value: '365',
        ignoreFocusOut: true,
        validateInput: v => /^\d+$/.test(v) && +v > 0 ? null : 'Enter a positive integer',
      });
      if (daysStr === undefined) return;

      const password = await vscode.window.showInputBox({
        title: 'Create Self-Signed P12 — Password',
        prompt: 'Password to protect the P12 (leave empty for no password)',
        password: true,
        ignoreFocusOut: true,
      });
      if (password === undefined) return;

      let p12Buf: Buffer;
      try {
        p12Buf = await vscode.window.withProgress(
          { location: vscode.ProgressLocation.Notification, title: 'Generating self-signed certificate…', cancellable: false },
          () => createSelfSignedP12(cn.trim(), parseInt(daysStr, 10), password),
        );
      } catch (err: unknown) {
        vscode.window.showErrorMessage(`Failed to generate certificate: ${(err as Error).message ?? String(err)}`);
        return;
      }

      const safeName = cn.trim().replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 64);
      const saveUri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(`${safeName}.p12`),
        filters: { 'PKCS#12 Files': ['p12', 'pfx'], 'All Files': ['*'] },
      });
      if (!saveUri) return;

      fs.writeFileSync(saveUri.fsPath, p12Buf);

      // Immediately open and display the generated cert in the viewer
      const panel = getOrCreatePanel(context.extensionUri, context);
      sendLoading(panel);
      try {
        const certs = await parseP12(p12Buf, password);
        sendCertificates(panel, certs, 0);
      } catch (err: unknown) {
        sendError(panel, (err as Error).message ?? String(err));
      }

      vscode.window.showInformationMessage(`Self-signed P12 saved to ${saveUri.fsPath}`);
    })
  );

  // Command: open the rich Create Certificate dialog
  context.subscriptions.push(
    vscode.commands.registerCommand('x509toolkit.createCertificate', () => {
      openCreateCertPanel(context.extensionUri, context);
    })
  );
}

export function deactivate(): void {
  // Nothing to clean up
}
