import * as assert from 'assert';
import type { ExtToWebviewMsg } from '@x509-toolkit/core';
import {
  requestInputDialog,
  requestPassphrase,
  resolveInputDialogRequest,
  resolvePassphraseRequest,
} from '../../utils/requestBridgeUtils';

suite('requestBridgeUtils', () => {
  test('requestPassphrase posts a request and resolves the matching response', async () => {
    const messages: unknown[] = [];
    const promise = requestPassphrase({ postMessage: (msg) => { messages.push(msg); } }, 'server.p12', {
      title: 'Unlock',
      requireConfirm: true,
    });

    assert.strictEqual(messages.length, 1);
    const message = messages[0] as ExtToWebviewMsg & { type: 'requestPassphrase' };
    assert.strictEqual(message.type, 'requestPassphrase');
    assert.strictEqual(message.fileName, 'server.p12');
    assert.strictEqual(message.title, 'Unlock');
    assert.strictEqual(message.requireConfirm, true);
    assert.strictEqual(resolvePassphraseRequest(message.requestId, 'secret'), true);
    assert.strictEqual(await promise, 'secret');
  });

  test('resolvePassphraseRequest returns false for unknown ids', () => {
    assert.strictEqual(resolvePassphraseRequest('missing', 'ignored'), false);
  });

  test('requestInputDialog posts a request and resolves matching values', async () => {
    const messages: unknown[] = [];
    const promise = requestInputDialog(
      { postMessage: (msg) => { messages.push(msg); } },
      'Validity',
      [{ id: 'days', label: 'Days', type: 'number' }],
      { confirmLabel: 'Continue' },
    );

    assert.strictEqual(messages.length, 1);
    const message = messages[0] as ExtToWebviewMsg & { type: 'requestInputDialog' };
    assert.strictEqual(message.type, 'requestInputDialog');
    assert.strictEqual(message.title, 'Validity');
    assert.strictEqual(message.confirmLabel, 'Continue');
    assert.strictEqual(message.fields[0].id, 'days');
    assert.strictEqual(resolveInputDialogRequest(message.requestId, { days: '365' }), true);
    assert.deepStrictEqual(await promise, { days: '365' });
  });

  test('resolveInputDialogRequest returns false for unknown ids', () => {
    assert.strictEqual(resolveInputDialogRequest('missing', { days: '7' }), false);
  });
});
