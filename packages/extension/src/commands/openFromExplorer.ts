import * as vscode from 'vscode';
import * as fs from 'fs';
import { sendParsedFile } from '../utils/handleX509Input';

export function openFromExplorer(
  context: vscode.ExtensionContext,
): (uri: vscode.Uri) => Promise<void> {
  return async (uri?: vscode.Uri) => {
    const targetUri = uri ?? vscode.window.activeTextEditor?.document.uri;
    if (!targetUri) {
      vscode.window.showErrorMessage('No file selected. Select a certificate file and try again.');
      return;
    }

    const filePath = targetUri.fsPath;
    const ext = filePath.toLowerCase().split('.').pop() ?? '';
    const fileName = filePath.split(/[\\/]/).pop() ?? 'file';

    try {
      await sendParsedFile(fs.readFileSync(filePath), ext, fileName, context);
    } catch (err: unknown) {
      vscode.window.showErrorMessage((err as Error).message ?? String(err));
    }
  };
}
