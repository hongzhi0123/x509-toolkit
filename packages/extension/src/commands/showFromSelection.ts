import * as vscode from 'vscode';
import { sendParsedPemText } from '../utils/handleX509Input';

export function showFromSelection(
  context: vscode.ExtensionContext,
): () => Promise<void> {
  return async () => {
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
        'No text selected. Please select PEM text and try again.'
      );
      return;
    }

    const text = selectedText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
    await sendParsedPemText(text, context);
  };
}
