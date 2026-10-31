import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { canonicalizePemBlocks, containsPemBlock, looksLikeKeyFile, parseCertificate, parseCsr, parseP12, parsePEMChain } from '@x509-toolkit/core';
import type { ExtToWebviewMsg, WebviewToExtMsg } from '@x509-toolkit/core';
import { buildHtml, createMessageQueue } from '../utils/webviewPanelUtils';
import { requestPassphrase, resolvePassphraseRequest } from '../utils/requestBridgeUtils';

const EDITOR_VIEW_TYPE = 'x509toolkit.certCsrViewerEditor';
const KEY_EDITOR_VIEW_TYPE = 'x509toolkit.keyViewerEditor';
const CRL_EDITOR_VIEW_TYPE = 'x509toolkit.crlViewerEditor';

const SUPPORTED_PATTERNS = ['*.pem', '*.crt', '*.cer', '*.der', '*.csr', '*.req'];
const P12_PATTERNS = ['*.p12', '*.pfx'];
const KEY_PATTERNS = ['*.key', '*.pk8', '*.p8', '*.pub'];
const CRL_PATTERNS = ['*.crl'];

type EditorAssociation = {
  viewType: string;
  filenamePattern: string;
};

type EditorAssociationMap = Record<string, string>;

function isCsrText(text: string): boolean {
  return (
    text.includes('-----BEGIN CERTIFICATE REQUEST-----') ||
    text.includes('-----BEGIN NEW CERTIFICATE REQUEST-----')
  );
}

function isPemCrlText(text: string): boolean {
  return text.includes('-----BEGIN X509 CRL-----');
}

function readFlag(): boolean {
  return vscode.workspace.getConfiguration('x509toolkit').get<boolean>('useCustomEditor.enabled', true);
}

async function promptPassphraseInInputBox(
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
): Promise<string | null> {
  const title = options?.title ?? 'P12 / PFX Password';
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

function hasCustomTab(uri: vscode.Uri, viewType: string): boolean {
  return vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .some((tab) => {
      const input = tab.input;
      return (
        input instanceof vscode.TabInputCustom &&
        input.viewType === viewType &&
        input.uri.toString() === uri.toString()
      );
    });
}

function hasAnyNonSourceTabForUri(uri: vscode.Uri, sourceViewType: string): boolean {
  return vscode.window.tabGroups.all
    .flatMap((group) => group.tabs)
    .some((tab) => {
      const input = tab.input;
      if (input instanceof vscode.TabInputCustom) {
        return input.uri.toString() === uri.toString() && input.viewType !== sourceViewType;
      }
      // Generic fallback for text-like tabs that expose uri.
      if (input && typeof input === 'object' && 'uri' in input) {
        const maybeUri = (input as { uri?: vscode.Uri }).uri;
        return !!maybeUri && maybeUri.toString() === uri.toString();
      }
      return false;
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

async function closeSourceTabsIfHandoffCompleted(
  uri: vscode.Uri,
  sourceViewType: string,
  targetViewType: string,
): Promise<void> {
  const targetReady = targetViewType === 'default'
    ? hasAnyNonSourceTabForUri(uri, sourceViewType)
    : hasCustomTab(uri, targetViewType);

  if (targetReady) {
    await closeSourceCustomTabs(uri, sourceViewType);
  }
}

async function sendDocumentToWebview(
  queue: ReturnType<typeof createMessageQueue<ExtToWebviewMsg>>,
  panel: vscode.WebviewPanel,
  fileName: string,
  raw: Buffer,
  asText: string,
  ext: string,
  requestPassphraseFromWebview: (
    fileName: string,
    options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
  ) => Promise<string | null>,
  cache?: { message?: ExtToWebviewMsg },
): Promise<void> {
  queue.post(panel, { type: 'loading' });

  if (ext === 'p12' || ext === 'pfx') {
    const ask = async (description: string): Promise<string | null> => requestPassphraseFromWebview(fileName, {
      title: 'P12 / PFX Password',
      description,
      buttonLabel: 'Open',
    });

    const first = await ask(`Enter the password for ${fileName}. Leave empty if the file has no password.`);
    if (first === null) {
      throw new Error('Operation cancelled.');
    }

    let certs;
    try {
      certs = await parseP12(raw, first);
    } catch {
      const second = await ask(`Incorrect password for ${fileName}. Try again.`);
      if (second === null) {
        throw new Error('Operation cancelled.');
      }
      certs = await parseP12(raw, second);
    }

    certs.forEach((cert) => { cert.sourceFormat = 'p12'; });
    const message: ExtToWebviewMsg = { type: 'certificate', chain: certs, activeIndex: 0 };
    cache && (cache.message = message);
    queue.post(panel, message);
    return;
  }

  if (ext === 'csr' || ext === 'req' || isCsrText(asText)) {
    const csrData = await parseCsr(raw);
    const message: ExtToWebviewMsg = { type: 'csr', data: csrData };
    cache && (cache.message = message);
    queue.post(panel, message);
    return;
  }

  if (asText.includes('-----BEGIN CERTIFICATE-----')) {
    const chain = await parsePEMChain(asText);
    chain.forEach((cert) => { cert.sourceFormat = 'pem'; });
    const message: ExtToWebviewMsg = { type: 'certificate', chain, activeIndex: 0 };
    cache && (cache.message = message);
    queue.post(panel, message);
    return;
  }

  const cert = await parseCertificate(raw);
  cert.sourceFormat = 'der';
  const message: ExtToWebviewMsg = { type: 'certificate', chain: [cert], activeIndex: 0 };
  cache && (cache.message = message);
  queue.post(panel, message);
}

class CertCsrCustomEditorProvider implements vscode.CustomReadonlyEditorProvider {
  constructor(private readonly context: vscode.ExtensionContext) {}

  async openCustomDocument(uri: vscode.Uri): Promise<vscode.CustomDocument> {
    return {
      uri,
      dispose: () => {
        // No-op.
      },
    };
  }

  async resolveCustomEditor(
    document: vscode.CustomDocument,
    webviewPanel: vscode.WebviewPanel,
  ): Promise<void> {
    const enabled = readFlag();
    if (!enabled) {
      await openWithViewPreservingPreview(document.uri, 'default', EDITOR_VIEW_TYPE);
      await closeSourceTabsIfHandoffCompleted(document.uri, EDITOR_VIEW_TYPE, 'default');
      return;
    }

    const raw = fs.readFileSync(document.uri.fsPath);
    const asText = raw.toString('utf8').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
    const normalizedText = containsPemBlock(asText) ? canonicalizePemBlocks(asText) : asText;
    const normalizedRaw = normalizedText === asText ? raw : Buffer.from(normalizedText, 'utf8');
    const ext = document.uri.fsPath.toLowerCase().split('.').pop() ?? '';
    const fileName = path.basename(document.uri.fsPath);

    if (isPemCrlText(normalizedText)) {
      await openWithViewPreservingPreview(document.uri, CRL_EDITOR_VIEW_TYPE, EDITOR_VIEW_TYPE);
      await closeSourceTabsIfHandoffCompleted(document.uri, EDITOR_VIEW_TYPE, CRL_EDITOR_VIEW_TYPE);
      return;
    }

    if (looksLikeKeyFile(normalizedRaw)) {
      await openWithViewPreservingPreview(document.uri, KEY_EDITOR_VIEW_TYPE, EDITOR_VIEW_TYPE);
      await closeSourceTabsIfHandoffCompleted(document.uri, EDITOR_VIEW_TYPE, KEY_EDITOR_VIEW_TYPE);
      return;
    }

    webviewPanel.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this.context.extensionUri, 'dist', 'webview')],
    };
    webviewPanel.webview.html = buildHtml(webviewPanel.webview, this.context.extensionUri, {
      title: 'X.509 Certificate / CSR Viewer',
    });

    const queue = createMessageQueue<ExtToWebviewMsg>();
    const renderedState: { message?: ExtToWebviewMsg } = {};
    let readyCount = 0;
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
      passphraseFileName: string,
      options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
    ): Promise<string | null> => requestPassphrase(
      { postMessage: (msg) => queue.post(webviewPanel, msg as ExtToWebviewMsg) },
      passphraseFileName,
      options,
    );

    const requestPassphraseSafely = async (
      passphraseFileName: string,
      options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean },
    ): Promise<string | null> => {
      const ready = await waitForReady(1500);
      if (!ready) {
        return promptPassphraseInInputBox(passphraseFileName, options);
      }

      const timeoutSentinel = '__timeout__' as const;
      const bridgeResult = await Promise.race<string | null | typeof timeoutSentinel>([
        requestPassphraseFromWebview(passphraseFileName, options),
        new Promise<typeof timeoutSentinel>((resolve) => {
          setTimeout(() => resolve(timeoutSentinel), 120000);
        }),
      ]);

      if (bridgeResult === timeoutSentinel) {
        void vscode.window.showWarningMessage('Passphrase dialog timed out. Falling back to VS Code input.');
        return promptPassphraseInInputBox(passphraseFileName, options);
      }

      return bridgeResult;
    };

    webviewPanel.webview.onDidReceiveMessage((msg: WebviewToExtMsg) => {
      switch (msg.type) {
        case 'ready':
          readyCount += 1;
          queue.ready = true;
          readyResolve?.();
          queue.flushPending(webviewPanel);
          if (readyCount > 1 && renderedState.message) {
            queue.post(webviewPanel, renderedState.message);
          }
          break;
        case 'copyToClipboard':
          void vscode.env.clipboard.writeText(msg.value);
          void vscode.window.showInformationMessage('Copied to clipboard.');
          break;
        case 'passphraseResponse':
          resolvePassphraseRequest(msg.requestId, msg.passphrase);
          break;
        default:
          break;
      }
    });

    try {
      await sendDocumentToWebview(
        queue,
        webviewPanel,
        fileName,
        normalizedRaw,
        normalizedText,
        ext,
        requestPassphraseSafely,
        renderedState,
      );
    } catch (error: unknown) {
      const message: ExtToWebviewMsg = { type: 'error', message: (error as Error).message ?? String(error) };
      renderedState.message = message;
      queue.post(webviewPanel, message);
    }
  }
}

function isOurViewType(viewType: string): boolean {
  return (
    viewType === EDITOR_VIEW_TYPE ||
    viewType === KEY_EDITOR_VIEW_TYPE ||
    viewType === CRL_EDITOR_VIEW_TYPE ||
    viewType === 'x509toolkit.certViewerEditor' ||
    viewType === 'x509toolkit.csrViewerEditor'
  );
}

function normalizeAssociationMap(current: unknown): EditorAssociationMap {
  // VS Code generally stores this as an object map. Keep support for legacy
  // array shape so migration stays resilient.
  if (Array.isArray(current)) {
    const map: EditorAssociationMap = {};
    for (const item of current) {
      if (!item || typeof item !== 'object') {
        continue;
      }
      const candidate = item as Partial<EditorAssociation>;
      if (typeof candidate.filenamePattern === 'string' && typeof candidate.viewType === 'string') {
        map[candidate.filenamePattern] = candidate.viewType;
      }
    }
    return map;
  }

  if (!current || typeof current !== 'object') {
    return {};
  }

  const map: EditorAssociationMap = {};
  for (const [pattern, viewType] of Object.entries(current as Record<string, unknown>)) {
    if (typeof viewType === 'string') {
      map[pattern] = viewType;
    }
  }
  return map;
}

function updateManagedAssociations(
  associations: EditorAssociationMap,
  enabled: boolean,
  mappings: Array<{ patterns: string[]; viewType: string }>,
): void {
  for (const mapping of mappings) {
    for (const pattern of mapping.patterns) {
      const existing = associations[pattern];
      if (!enabled) {
        if (existing && isOurViewType(existing)) {
          delete associations[pattern];
        }
        continue;
      }

      associations[pattern] = mapping.viewType;
    }
  }
}

export async function syncCustomEditorAssociations(): Promise<void> {
  const enabled = readFlag();

  const workbenchConfig = vscode.workspace.getConfiguration('workbench');
  const current = workbenchConfig.get<unknown>('editorAssociations', {});
  const currentMap = normalizeAssociationMap(current);
  const updatedMap = { ...currentMap };

  updateManagedAssociations(updatedMap, enabled, [
    { patterns: SUPPORTED_PATTERNS, viewType: EDITOR_VIEW_TYPE },
    { patterns: P12_PATTERNS, viewType: EDITOR_VIEW_TYPE },
    { patterns: KEY_PATTERNS, viewType: KEY_EDITOR_VIEW_TYPE },
    { patterns: CRL_PATTERNS, viewType: CRL_EDITOR_VIEW_TYPE },
  ]);

  const currentJson = JSON.stringify(currentMap);
  const updatedJson = JSON.stringify(updatedMap);
  if (currentJson === updatedJson) {
    return;
  }

  await workbenchConfig.update('editorAssociations', updatedMap, vscode.ConfigurationTarget.Global);
}

export function registerCertCsrCustomEditors(context: vscode.ExtensionContext): vscode.Disposable[] {
  return [
    vscode.window.registerCustomEditorProvider(
      EDITOR_VIEW_TYPE,
      new CertCsrCustomEditorProvider(context),
      { supportsMultipleEditorsPerDocument: true },
    ),
  ];
}
