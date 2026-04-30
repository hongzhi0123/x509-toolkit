import * as vscode from 'vscode';
import * as fs from 'fs';
import { parseCertificate, parsePEMChain } from './certificateParser';
import { parseP12 } from './p12Parser';
import {
  getOrCreatePanel,
  sendLoading,
  sendCertificates,
  sendError,
} from './panelManager';

async function openP12File(
  filePath: string,
  panel: ReturnType<typeof getOrCreatePanel>,
): Promise<void> {
  const password = await vscode.window.showInputBox({
    title: 'P12 / PFX Password',
    prompt: 'Enter the password for this PKCS#12 file (leave empty if none)',
    password: true,
    ignoreFocusOut: true,
  });

  // undefined means the user pressed Escape
  if (password === undefined) {
    sendError(panel, 'Operation cancelled.');
    return;
  }

  const raw = fs.readFileSync(filePath);
  const certs = await parseP12(raw, password);
  sendCertificates(panel, certs, 0);
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('x509viewer.showFromSelection', async () => {
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
    vscode.commands.registerCommand('x509viewer.openFile', async () => {
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
    vscode.commands.registerCommand('x509viewer.openP12', async () => {
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
}

export function deactivate(): void {
  // Nothing to clean up
}
