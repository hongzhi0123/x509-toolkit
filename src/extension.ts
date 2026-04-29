import * as vscode from 'vscode';
import * as fs from 'fs';
import { parseCertificate, parsePEMChain } from './certificateParser';
import {
  getOrCreatePanel,
  sendLoading,
  sendCertificates,
  sendError,
} from './panelManager';

export function activate(context: vscode.ExtensionContext): void {
  // Command: parse certificate from editor selection
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

  // Command: open certificate file (PEM or DER)
  context.subscriptions.push(
    vscode.commands.registerCommand('x509viewer.openFile', async () => {
      const uris = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Open Certificate',
        filters: {
          'Certificate Files': ['pem', 'crt', 'cer', 'der', 'p7b', 'p7c'],
          'All Files': ['*'],
        },
      });

      if (!uris || uris.length === 0) return;

      const filePath = uris[0].fsPath;
      const panel = getOrCreatePanel(context.extensionUri, context);
      sendLoading(panel);

      try {
        const raw = fs.readFileSync(filePath);
        const asText = raw.toString('utf8');

        if (asText.includes('-----BEGIN CERTIFICATE-----')) {
          // PEM file – may contain a chain
          const chain = await parsePEMChain(asText);
          sendCertificates(panel, chain, 0);
        } else {
          // Assume DER binary
          const cert = await parseCertificate(raw);
          sendCertificates(panel, [cert], 0);
        }
      } catch (err: unknown) {
        sendError(panel, (err as Error).message ?? String(err));
      }
    })
  );
}

export function deactivate(): void {
  // Nothing to clean up
}
