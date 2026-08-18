import * as assert from 'assert';
import type { ExtToWebviewMsg } from '@x509-toolkit/core';
import {
  importPrivateKey,
  type KeyImportHost,
  type KeyImportValidator,
} from '../../utils/keyImportUtils';

function createHost(overrides?: {
  selectedPath?: string | undefined;
  fileContent?: Buffer;
  passphrases?: Array<string | null>;
}) {
  const messages: ExtToWebviewMsg[] = [];
  const requestedPassphrases: string[] = [];
  const openDialogCalls: string[] = [];
  const passphrases = [...(overrides?.passphrases ?? [])];

  const host: KeyImportHost = {
    showOpenDialog: async (options) => {
      openDialogCalls.push(options.title);
      return overrides?.selectedPath;
    },
    readFile: () => overrides?.fileContent ?? Buffer.from('-----BEGIN PRIVATE KEY-----\nabc', 'utf8'),
    requestPassphrase: async (fileName) => {
      requestedPassphrases.push(fileName);
      return passphrases.shift() ?? null;
    },
    postMessage: (message) => {
      messages.push(message);
    },
  };

  return { host, messages, requestedPassphrases, openDialogCalls };
}

suite('keyImportUtils', () => {
  test('returns early when user cancels file selection', async () => {
    const { host, messages } = createHost({ selectedPath: undefined });
    const validator: KeyImportValidator = () => ({ ok: true });
    await importPrivateKey(host, { type: 'importPrivateKey', certIndex: 0, spkiPem: 'spki' }, validator);
    assert.strictEqual(messages.length, 0);
  });

  test('imports an unencrypted private key successfully', async () => {
    const { host, messages, requestedPassphrases } = createHost({ selectedPath: 'c:/tmp/key.pem' });
    const validator: KeyImportValidator = () => ({ algorithm: 'RSA' });

    await importPrivateKey(host, { type: 'importPrivateKey', certIndex: 2, spkiPem: 'spki' }, validator);

    assert.deepStrictEqual(requestedPassphrases, []);
    assert.deepStrictEqual(messages, [{ type: 'privateKeyImported', certIndex: 2, key: { algorithm: 'RSA' } }]);
  });

  test('prompts immediately for encrypted PEM input', async () => {
    const { host, messages, requestedPassphrases } = createHost({
      selectedPath: 'c:/tmp/secure.key',
      fileContent: Buffer.from('-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc', 'utf8'),
      passphrases: ['secret'],
    });
    let receivedPassphrase: string | undefined;
    const validator: KeyImportValidator = (_buf, _spki, passphrase) => {
      receivedPassphrase = passphrase;
      return { ok: true };
    };

    await importPrivateKey(host, { type: 'importPrivateKey', certIndex: 1, spkiPem: 'spki' }, validator);

    assert.deepStrictEqual(requestedPassphrases, ['secure.key']);
    assert.strictEqual(receivedPassphrase, 'secret');
    assert.strictEqual(messages[0].type, 'privateKeyImported');
  });

  test('retries with passphrase when validator indicates encrypted key', async () => {
    const { host, messages, requestedPassphrases } = createHost({
      selectedPath: 'c:/tmp/key.pem',
      passphrases: ['retry-pass'],
    });
    let attempts = 0;
    const validator: KeyImportValidator = (_buf, _spki, passphrase) => {
      attempts += 1;
      if (!passphrase) {
        throw new Error('bad decrypt');
      }
      return { unlocked: true };
    };

    await importPrivateKey(host, { type: 'importPrivateKey', certIndex: 4, spkiPem: 'spki' }, validator);

    assert.strictEqual(attempts, 2);
    assert.deepStrictEqual(requestedPassphrases, ['key.pem']);
    assert.deepStrictEqual(messages, [{ type: 'privateKeyImported', certIndex: 4, key: { unlocked: true } }]);
  });

  test('posts import error when retry still fails', async () => {
    const { host, messages } = createHost({
      selectedPath: 'c:/tmp/key.pem',
      passphrases: ['wrong-pass'],
    });
    const validator: KeyImportValidator = () => {
      throw new Error('still encrypted');
    };

    await importPrivateKey(host, { type: 'importPrivateKey', certIndex: 5, spkiPem: 'spki' }, validator);

    assert.deepStrictEqual(messages, [{ type: 'privateKeyImportError', certIndex: 5, message: 'still encrypted' }]);
  });
});
