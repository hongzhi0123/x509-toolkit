import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
  isEncryptedKey,
  parseCrl,
  parseKeyFile,
  parsePemCrlChain,
  type CrlViewerToExtMsg,
  type ExtToCrlViewerMsg,
  type ExtToKeyViewerMsg,
  type KeyViewerToExtMsg,
} from '@x509-toolkit/core';
import { requestPassphrase, resolvePassphraseRequest } from '../utils/requestBridgeUtils';
import { buildHtml, createMessageQueue } from '../utils/webviewPanelUtils';

const KEY_EDITOR_VIEW_TYPE = 'x509toolkit.keyViewerEditor';
const CRL_EDITOR_VIEW_TYPE = 'x509toolkit.crlViewerEditor';

function readFlag(): boolean {
  return vscode.workspace.getConfiguration('x509toolkit').get<boolean>('useCustomEditor.enabled', true);
}

async function openLegacyFlow(uri: vscode.Uri): Promise<void> {
  await vscode.commands.executeCommand('x509toolkit.openFromExplorer', uri);
}

async function openWithView(uri: vscode.Uri, viewType: string): Promise<void> {
  await vscode.commands.executeCommand('vscode.openWith', uri, viewType);
}

function findSourceCustomTab(uri: vscode.Uri, viewType: string): vscode.Tab | undefined {
  return vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .find((tab) => {
      const input = tab.input;
      return (
        input instanceof vscode.TabInputCustom &&
        input.viewType === viewType &&
        input.uri.toString() === uri.toString()
      );
    });
}

async function openWithViewPreservingPreview(uri: vscode.Uri, targetViewType: string, sourceViewType: string): Promise<void> {
  const sourceTab = findSourceCustomTab(uri, sourceViewType);
  const options: vscode.TextDocumentShowOptions = {
    viewColumn: sourceTab?.group.viewColumn,
    preview: sourceTab?.isPreview,
    preserveFocus: !sourceTab?.isActive,
  };
  await vscode.commands.executeCommand('vscode.openWith', uri, targetViewType, options);
}

async function closeSourceCustomTabs(uri: vscode.Uri, viewType: string): Promise<void> {
  const matched = vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .filter((tab) => {
      const input = tab.input;
      return (
        input instanceof vscode.TabInputCustom &&
        input.viewType === viewType &&
        input.uri.toString() === uri.toString()
      );
    });

  if (matched.length > 0) {
    await vscode.window.tabGroups.close(matched, true);
  }
}

async function promptPassphraseInInputBox(
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
): Promise<string | null> {
  const title = options?.title ?? 'Key File Passphrase';
  const prompt = options?.description ?? `Enter passphrase for ${fileName}.`;

  const first = await vscode.window.showInputBox({
    title,
    prompt,
    password: true,
    ignoreFocusOut: true,
  });
  if (first === undefined) {
    return null;
  }

  if (!options?.requireConfirm) {
    return first;
  }

  const second = await vscode.window.showInputBox({
    title,
    prompt: 'Confirm passphrase',
    password: true,
    ignoreFocusOut: true,
  });
  if (second === undefined) {
    return null;
  }

  if (first !== second) {
    void vscode.window.showErrorMessage('Passphrases do not match.');
    return null;
  }

  return first;
}

class KeyCustomEditorProvider implements vscode.CustomReadonlyEditorProvider {
  constructor(private readonly context: vscode.ExtensionContext) {}

  async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> {
    return {
      uri,
      dispose: () => {
        // No-op.
      },
    };
  }

  async resolveCustomEditor(document: vscode.CustomDocument, webviewPanel: vscode.WebviewPanel): Promise<void> {
    if (!readFlag()) {
      await openWithViewPreservingPreview(document.uri, 'default', KEY_EDITOR_VIEW_TYPE);
      await closeSourceCustomTabs(document.uri, KEY_EDITOR_VIEW_TYPE);
      return;
    }

    webviewPanel.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.context.extensionUri, 'dist', 'webview')],
    };
    webviewPanel.webview.html = buildHtml(webviewPanel.webview, this.context.extensionUri, {
      title: 'X.509 Key Viewer',
      dataView: 'keyViewer',
    });

    const queue = createMessageQueue<ExtToKeyViewerMsg>();
    let heldNodeKey: crypto.KeyObject | undefined;
    let readyCount = 0;
    let renderedState: ExtToKeyViewerMsg | undefined;
    let readyResolve: (() => void) | undefined;
    const readyPromise = new Promise<void>((resolve) => {
      readyResolve = resolve;
    });

    const waitForReady = async (timeoutMs: number): Promise<boolean> => {
      if (queue.ready) {
        return true;
      }
      const readySignal = readyPromise.then(() => true);
      const timeoutSignal = new Promise<boolean>((resolve) => {
        setTimeout(() => resolve(false), timeoutMs);
      });
      return Promise.race([readySignal, timeoutSignal]);
    };

    const requestPassphraseFromWebview = (
      fileName: string,
      options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
    ): Promise<string | null> => requestPassphrase(
      { postMessage: (msg) => queue.post(webviewPanel, msg as ExtToKeyViewerMsg) },
      fileName,
      options,
    );

    const requestPassphraseSafely = async (
      fileName: string,
      options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
    ): Promise<string | null> => {
      const ready = await waitForReady(1500);
      if (!ready) {
        return promptPassphraseInInputBox(fileName, options);
      }

      const timeoutSentinel = '__timeout__' as const;
      const bridgeResult = await Promise.race<string | null | typeof timeoutSentinel>([
        requestPassphraseFromWebview(fileName, options),
        new Promise<typeof timeoutSentinel>((resolve) => {
          setTimeout(() => resolve(timeoutSentinel), 120000);
        }),
      ]);

      if (bridgeResult === timeoutSentinel) {
        void vscode.window.showWarningMessage('Passphrase dialog timed out. Falling back to VS Code input.');
        return promptPassphraseInInputBox(fileName, options);
      }

      return bridgeResult;
    };

    webviewPanel.webview.onDidReceiveMessage(async (msg: KeyViewerToExtMsg) => {
      switch (msg.type) {
        case 'keyViewerReady':
          readyCount += 1;
          queue.ready = true;
          readyResolve?.();
          queue.flushPending(webviewPanel);
          if (readyCount > 1 && renderedState) {
            queue.post(webviewPanel, renderedState);
          }
          break;

        case 'copyToClipboard':
          void vscode.env.clipboard.writeText(msg.value);
          void vscode.window.showInformationMessage('Copied to clipboard.');
          break;

        case 'passphraseResponse':
          resolvePassphraseRequest(msg.requestId, msg.passphrase);
          break;

        case 'exportPrivateKey': {
          if (!heldNodeKey || heldNodeKey.type !== 'private') break;
          const { format, encrypt, suggestedName } = msg;

          let passphrase: string | undefined;
          if (encrypt) {
            const pp = await requestPassphraseFromWebview(suggestedName, {
              title: 'Encrypt Private Key',
              description: 'Enter a passphrase to protect the exported key. Leave empty for no encryption.',
              buttonLabel: 'Export',
              requireConfirm: true,
            });
            if (pp === null) break;
            passphrase = pp || undefined;
          }

          try {
            let data: Buffer;
            const isText = format.endsWith('-pem');
            switch (format) {
              case 'pkcs8-pem':
                data = Buffer.from(
                  heldNodeKey.export(
                    passphrase
                      ? { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
                      : { type: 'pkcs8', format: 'pem' },
                  ) as string,
                  'utf8',
                );
                break;
              case 'pkcs8-der':
                data = heldNodeKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
                break;
              case 'pkcs1-pem':
                data = Buffer.from(heldNodeKey.export({ type: 'pkcs1', format: 'pem' }) as string, 'utf8');
                break;
              case 'pkcs1-der':
                data = heldNodeKey.export({ type: 'pkcs1', format: 'der' }) as Buffer;
                break;
              case 'sec1-pem':
                data = Buffer.from(heldNodeKey.export({ type: 'sec1', format: 'pem' }) as string, 'utf8');
                break;
              case 'sec1-der':
                data = heldNodeKey.export({ type: 'sec1', format: 'der' }) as Buffer;
                break;
              default:
                void vscode.window.showErrorMessage('Unknown export format.');
                return;
            }

            const ext = isText ? 'pem' : 'der';
            const uri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file(`${suggestedName}.${ext}`),
              filters: isText
                ? { 'Private Key': ['pem', 'key'], 'All Files': ['*'] }
                : { 'DER Key': ['der', 'key'], 'All Files': ['*'] },
              saveLabel: 'Export Key',
              title: 'Save Private Key',
            });
            if (!uri) break;
            fs.writeFileSync(uri.fsPath, data);
            void vscode.window.showInformationMessage(`Key saved to ${path.basename(uri.fsPath)}`);
          } catch (e) {
            void vscode.window.showErrorMessage(`Export failed: ${(e as Error).message}`);
          }
          break;
        }

        case 'exportPublicKey': {
          if (!heldNodeKey) break;
          const { format, suggestedName } = msg;
          try {
            const pubKey = heldNodeKey.type === 'public'
              ? heldNodeKey
              : crypto.createPublicKey(heldNodeKey);
            const isText = format === 'spki-pem';
            const data = isText
              ? Buffer.from(pubKey.export({ type: 'spki', format: 'pem' }) as string, 'utf8')
              : (pubKey.export({ type: 'spki', format: 'der' }) as Buffer);

            const ext = isText ? 'pem' : 'der';
            const uri = await vscode.window.showSaveDialog({
              defaultUri: vscode.Uri.file(`${suggestedName}.${ext}`),
              filters: isText
                ? { 'Public Key': ['pem', 'pub'], 'All Files': ['*'] }
                : { 'DER Public Key': ['der', 'pub'], 'All Files': ['*'] },
              saveLabel: 'Export Public Key',
              title: 'Save Public Key',
            });
            if (!uri) break;
            fs.writeFileSync(uri.fsPath, data);
            void vscode.window.showInformationMessage(`Public key saved to ${path.basename(uri.fsPath)}`);
          } catch (e) {
            void vscode.window.showErrorMessage(`Export failed: ${(e as Error).message}`);
          }
          break;
        }

        default:
          break;
      }
    });

    queue.post(webviewPanel, { type: 'keyLoading' });

    const buf = fs.readFileSync(document.uri.fsPath);
    const displayName = path.basename(document.uri.fsPath);
    const encrypted = isEncryptedKey(buf);

    const tryParse = async (passphrase?: string): Promise<boolean> => {
      try {
        const { data, nodeKey } = parseKeyFile(buf, passphrase);
        heldNodeKey = nodeKey;
        const message: ExtToKeyViewerMsg = { type: 'keyData', key: data };
        renderedState = message;
        queue.post(webviewPanel, message);
        return true;
      } catch {
        return false;
      }
    };

    if (encrypted) {
      const passphrase = await requestPassphraseSafely(displayName, {
        title: 'Key File Passphrase',
        description: `${displayName} is encrypted. Enter its passphrase.`,
        buttonLabel: 'Open',
      });
      if (passphrase === null) {
        renderedState = { type: 'keyError', message: 'Operation cancelled.' };
        queue.post(webviewPanel, renderedState);
        return;
      }
      const ok = await tryParse(passphrase);
      if (!ok) {
        const pp2 = await requestPassphraseSafely(displayName, {
          title: 'Key File Passphrase',
          description: `Incorrect passphrase for ${displayName}. Try again.`,
          buttonLabel: 'Open',
        });
        if (pp2 === null) {
          renderedState = { type: 'keyError', message: 'Operation cancelled.' };
          queue.post(webviewPanel, renderedState);
          return;
        }
        const ok2 = await tryParse(pp2);
        if (!ok2) {
          renderedState = { type: 'keyError', message: 'Incorrect passphrase or corrupted key file.' };
          queue.post(webviewPanel, renderedState);
        }
      }
      return;
    }

    const ok = await tryParse();
    if (!ok) {
      renderedState = {
        type: 'keyError',
        message: 'Failed to parse key - not a recognised private or public key format.',
      };
      queue.post(webviewPanel, renderedState);
    }
  }
}

class CrlCustomEditorProvider implements vscode.CustomReadonlyEditorProvider {
  constructor(private readonly context: vscode.ExtensionContext) {}

  async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> {
    return {
      uri,
      dispose: () => {
        // No-op.
      },
    };
  }

  async resolveCustomEditor(document: vscode.CustomDocument, webviewPanel: vscode.WebviewPanel): Promise<void> {
    if (!readFlag()) {
      await openWithViewPreservingPreview(document.uri, 'default', CRL_EDITOR_VIEW_TYPE);
      await closeSourceCustomTabs(document.uri, CRL_EDITOR_VIEW_TYPE);
      return;
    }

    webviewPanel.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.context.extensionUri, 'dist', 'webview')],
    };
    webviewPanel.webview.html = buildHtml(webviewPanel.webview, this.context.extensionUri, {
      title: 'X.509 CRL Viewer',
      dataView: 'crlViewer',
    });

    const queue = createMessageQueue<ExtToCrlViewerMsg>();
    let readyCount = 0;
    let renderedState: ExtToCrlViewerMsg | undefined;
    webviewPanel.webview.onDidReceiveMessage((msg: CrlViewerToExtMsg) => {
      switch (msg.type) {
        case 'crlViewerReady':
          readyCount += 1;
          queue.ready = true;
          queue.flushPending(webviewPanel);
          if (readyCount > 1 && renderedState) {
            queue.post(webviewPanel, renderedState);
          }
          break;
        case 'copyToClipboard':
          void vscode.env.clipboard.writeText(msg.value);
          void vscode.window.showInformationMessage('Copied to clipboard.');
          break;
        default:
          break;
      }
    });

    queue.post(webviewPanel, { type: 'crlLoading' });

    try {
      const raw = fs.readFileSync(document.uri.fsPath);
      const asciiHead = raw.toString('ascii', 0, 64);
      const ext = document.uri.fsPath.toLowerCase().split('.').pop() ?? '';

      const crls = (ext === 'pem' || asciiHead.includes('-----BEGIN'))
        ? parsePemCrlChain(raw)
        : [parseCrl(raw)];

      if (crls.length === 0) {
        renderedState = { type: 'crlError', message: 'No CRL entries found in file.' };
        queue.post(webviewPanel, renderedState);
        return;
      }

      renderedState = { type: 'crlData', crl: crls[0] };
      queue.post(webviewPanel, renderedState);
    } catch (err: unknown) {
      renderedState = { type: 'crlError', message: (err as Error).message ?? String(err) };
      queue.post(webviewPanel, renderedState);
    }
  }
}

export function registerKeyCrlCustomEditors(context: vscode.ExtensionContext): vscode.Disposable[] {
  return [
    vscode.window.registerCustomEditorProvider(
      KEY_EDITOR_VIEW_TYPE,
      new KeyCustomEditorProvider(context),
      { supportsMultipleEditorsPerDocument: true },
    ),
    vscode.window.registerCustomEditorProvider(
      CRL_EDITOR_VIEW_TYPE,
      new CrlCustomEditorProvider(context),
      { supportsMultipleEditorsPerDocument: true },
    ),
  ];
}
