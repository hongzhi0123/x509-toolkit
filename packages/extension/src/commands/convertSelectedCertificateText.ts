import * as vscode from 'vscode';
import { canonicalizePemBlocks, containsPemBlock, toOneLinePem, toRawBase64 } from '@x509-toolkit/core';

type ConvertOutputMode = 'pem-wrapped' | 'pem-single-line' | 'base64';
type ConvertDestination = 'replace-selection' | 'copy' | 'new-document';

function convertPemText(input: string, mode: ConvertOutputMode): string {
  if (mode === 'pem-wrapped') {
    return canonicalizePemBlocks(input);
  }
  if (mode === 'pem-single-line') {
    return toOneLinePem(input);
  }
  return toRawBase64(input);
}

export function convertSelectedCertificateText(): () => Promise<void> {
  return async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('No active editor found.');
      return;
    }

    const selection = editor.selection;
    if (selection.isEmpty) {
      vscode.window.showWarningMessage('No text selected. Select certificate PEM text and try again.');
      return;
    }

    const selectedText = editor.document.getText(selection);
    const normalizedInput = selectedText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
    if (!containsPemBlock(normalizedInput)) {
      vscode.window.showWarningMessage('Selected text does not contain PEM certificate markers.');
      return;
    }

    const modePick = await vscode.window.showQuickPick(
      [
        { label: 'PEM (64-char wrapped)', mode: 'pem-wrapped' as const },
        { label: 'PEM (single line)', mode: 'pem-single-line' as const },
        { label: 'Base64 only (no markers)', mode: 'base64' as const },
      ],
      {
        title: 'Convert Selected Certificate Text',
        placeHolder: 'Choose output format',
        ignoreFocusOut: true,
      },
    );

    if (!modePick) {
      return;
    }

    const destinationPick = await vscode.window.showQuickPick(
      [
        { label: 'Replace selection', destination: 'replace-selection' as const },
        { label: 'Copy to clipboard', destination: 'copy' as const },
        { label: 'Open in new document', destination: 'new-document' as const },
      ],
      {
        title: 'Convert Selected Certificate Text',
        placeHolder: 'Choose output destination',
        ignoreFocusOut: true,
      },
    );

    if (!destinationPick) {
      return;
    }

    const converted = convertPemText(normalizedInput, modePick.mode);

    if (destinationPick.destination === 'copy') {
      await vscode.env.clipboard.writeText(converted);
      vscode.window.showInformationMessage('Converted certificate text copied to clipboard.');
      return;
    }

    if (destinationPick.destination === 'new-document') {
      const doc = await vscode.workspace.openTextDocument({
        content: converted,
        language: editor.document.languageId,
      });
      await vscode.window.showTextDocument(doc, { preview: false });
      return;
    }

    const applied = await editor.edit((editBuilder) => {
      editBuilder.replace(selection, converted);
    });

    if (!applied) {
      vscode.window.showWarningMessage('Failed to replace the selected text.');
      return;
    }

    vscode.window.showInformationMessage('Selected certificate text converted.');
  };
}
