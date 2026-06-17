import type { InputDialogFieldDef } from '@x509-toolkit/core';

export const pendingPassphraseRequests = new Map<string, (passphrase: string | null) => void>();
export const pendingInputDialogRequests = new Map<string, (values: Record<string, string> | null) => void>();

export function createRequestId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

export function requestInputDialog(
  webview: { postMessage(message: unknown): unknown },
  title: string,
  fields: InputDialogFieldDef[],
  options?: { icon?: string; description?: string; confirmLabel?: string; cancelLabel?: string }
): Promise<Record<string, string> | null> {
  const requestId = createRequestId('idlg');
  return new Promise(resolve => {
    pendingInputDialogRequests.set(requestId, resolve);
    webview.postMessage({ type: 'requestInputDialog', requestId, title, fields, ...options });
  });
}

export function requestPassphrase(
  webview: { postMessage(message: unknown): unknown },
  fileName: string,
  options?: { title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean }
): Promise<string | null> {
  const requestId = createRequestId('pp');
  return new Promise(resolve => {
    pendingPassphraseRequests.set(requestId, resolve);
    webview.postMessage({ type: 'requestPassphrase', requestId, fileName, ...options });
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
