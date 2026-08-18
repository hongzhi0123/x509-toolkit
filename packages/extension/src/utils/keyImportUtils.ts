import * as crypto from 'crypto';
import type { ExtToWebviewMsg, WebviewToExtMsg } from '@x509-toolkit/core';
import { isEncryptedKey } from '@x509-toolkit/core';

type OpenDialogOptions = {
  canSelectMany: boolean;
  openLabel: string;
  title: string;
  filters: { [name: string]: string[] };
};

export type KeyImportHost = {
  showOpenDialog(options: OpenDialogOptions): Promise<string | undefined>;
  readFile(path: string): Buffer;
  requestPassphrase(fileName: string): Promise<string | null>;
  postMessage(message: ExtToWebviewMsg): void;
};

export type KeyImportValidatorResult = unknown;

export type KeyImportValidator = (
  keyBuffer: Buffer,
  spkiPem: string,
  passphrase?: string
) => KeyImportValidatorResult;

function getFileName(filePath: string): string {
  return filePath.split(/[\\/]/).pop() ?? 'private key';
}

function shouldRetryWithPassphrase(errorMessage: string): boolean {
  return /passphrase|bad decrypt|encrypt|unsupported|interrupt/i.test(errorMessage);
}

/**
 * Attempt to load a private key, prompting for a passphrase if it is encrypted.
 * Returns the parsed KeyObject, or `null` if the user cancelled the passphrase prompt.
 * Re-throws the original error for non-passphrase-related failures.
 */
export async function tryLoadPrivateKey(
  keyInput: string | Buffer,
  requestPassphrase: () => Promise<string | null>,
): Promise<crypto.KeyObject | null> {
  try {
    return crypto.createPrivateKey(keyInput);
  } catch (firstErr) {
    const msg = (firstErr as Error).message ?? '';
    if (/passphrase|encrypted|bad decrypt|EVP_|PKCS/i.test(msg)) {
      const passphrase = await requestPassphrase();
      if (passphrase === null) return null;
      return crypto.createPrivateKey({ key: keyInput, passphrase });
    }
    throw firstErr;
  }
}

export async function importPrivateKey(
  host: KeyImportHost,
  msg: Extract<WebviewToExtMsg, { type: 'importPrivateKey' }>,
  validatePrivateKey: KeyImportValidator
): Promise<void> {
  const keyPath = await host.showOpenDialog({
    canSelectMany: false,
    openLabel: 'Import Private Key',
    title: 'Select Private Key File (PEM or DER)',
    filters: {
      'Private Key': ['pem', 'key', 'der', 'pk8'],
      'All Files': ['*'],
    },
  });
  if (!keyPath) {
    return;
  }

  const keyBuffer = host.readFile(keyPath);
  const fileName = getFileName(keyPath);

  let passphrase: string | undefined;
  if (isEncryptedKey(keyBuffer)) {
    const input = await host.requestPassphrase(fileName);
    if (input === null) {
      return;
    }
    passphrase = input;
  }

  const postKeyResult = async (currentPassphrase: string | undefined): Promise<true | Error> => {
    try {
      const key = validatePrivateKey(keyBuffer, msg.spkiPem, currentPassphrase);
      host.postMessage({ type: 'privateKeyImported', certIndex: msg.certIndex, key } as ExtToWebviewMsg);
      return true;
    } catch (error) {
      return error as Error;
    }
  };

  const result = await postKeyResult(passphrase);
  if (result === true) {
    return;
  }

  const errorMessage = result.message;
  if (!passphrase && shouldRetryWithPassphrase(errorMessage)) {
    const retryPassphrase = await host.requestPassphrase(fileName);
    if (retryPassphrase === null) {
      return;
    }
    const retry = await postKeyResult(retryPassphrase);
    if (retry !== true) {
      host.postMessage({
        type: 'privateKeyImportError',
        certIndex: msg.certIndex,
        message: retry.message,
      } as ExtToWebviewMsg);
    }
    return;
  }

  host.postMessage({
    type: 'privateKeyImportError',
    certIndex: msg.certIndex,
    message: errorMessage,
  } as ExtToWebviewMsg);
}
