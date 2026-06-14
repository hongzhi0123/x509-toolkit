import * as vscode from 'vscode';
import * as fs from 'fs';
import { getOrCreatePanel, sendLoading, sendError } from '../panels/mainViewerPanel';
import { sendParsedFile } from '../utils/handleX509Input';

export function openFromExplorer(
  context: vscode.ExtensionContext,
): (uri: vscode.Uri) => Promise<void> {
  return async (uri: vscode.Uri) => {
    const filePath = uri.fsPath;
    const ext = filePath.toLowerCase().split('.').pop() ?? '';
    const fileName = filePath.split(/[\\/]/).pop() ?? 'file';

    const panel = getOrCreatePanel(context.extensionUri, context);
    sendLoading(panel);

    try {
      await sendParsedFile(fs.readFileSync(filePath), ext, fileName, panel);
    } catch (err: unknown) {
      sendError(panel, (err as Error).message ?? String(err));
    }
  };
}
