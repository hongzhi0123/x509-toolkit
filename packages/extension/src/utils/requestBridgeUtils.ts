import type { ExtToWebviewMsg, InputDialogFieldDef } from '@x509-toolkit/core';

type WebviewMessageSink = {
  postMessage(message: ExtToWebviewMsg): unknown;
};

const pendingPassphraseRequests = new Map<string, (passphrase: string | null) => void>();
const pendingInputDialogRequests = new Map<string, (values: Record<string, string> | null) => void>();

function createRequestId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function requestInputDialog(
  webview: WebviewMessageSink,
  title: string,
  fields: InputDialogFieldDef[],
  options?: { icon?: string; description?: string; confirmLabel?: string; cancelLabel?: string }
): Promise<Record<string, string> | null> {
  const requestId = createRequestId('idlg');
  return new Promise(resolve => {
    pendingInputDialogRequests.set(requestId, resolve);
    const msg: ExtToWebviewMsg = { type: 'requestInputDialog', requestId, title, fields, ...options };
    webview.postMessage(msg);
  });
}

export function requestPassphrase(
  webview: WebviewMessageSink,
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean }
): Promise<string | null> {
  const requestId = createRequestId('pp');
  return new Promise(resolve => {
    pendingPassphraseRequests.set(requestId, resolve);
    const msg: ExtToWebviewMsg = { type: 'requestPassphrase', requestId, fileName, ...options };
    webview.postMessage(msg);
  });
}

export function resolvePassphraseRequest(requestId: string, passphrase: string | null): boolean {
  const resolve = pendingPassphraseRequests.get(requestId);
  if (!resolve) {
    return false;
  }
  pendingPassphraseRequests.delete(requestId);
  resolve(passphrase);
  return true;
}

export function resolveInputDialogRequest(requestId: string, values: Record<string, string> | null): boolean {
  const resolve = pendingInputDialogRequests.get(requestId);
  if (!resolve) {
    return false;
  }
  pendingInputDialogRequests.delete(requestId);
  resolve(values);
  return true;
}
