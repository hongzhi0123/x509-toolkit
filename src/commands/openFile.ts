import * as vscode from 'vscode';
import * as fs from 'fs';
import { getOrCreatePanel, sendLoading, sendError } from '../panels/panelManager';
import { sendParsedFile } from '../utils/handleX509Input';

export function openFile(
  context: vscode.ExtensionContext,
): () => Promise<void> {
  return async () => {
    const uris = await vscode.window.showOpenDialog({
      canSelectMany: false,
      openLabel: 'Open X.509 File',
      filters: {
        'X.509 Files': ['pem', 'crt', 'cer', 'der', 'p7b', 'p7c', 'p12', 'pfx', 'csr', 'req'],
        'All Files': ['*'],
      },
    });

    if (!uris || uris.length === 0) return;

    const filePath = uris[0].fsPath;
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
