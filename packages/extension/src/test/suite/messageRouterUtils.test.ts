import * as assert from 'assert';
import type { WebviewToExtMsg } from '@x509-toolkit/core';
import {
  routeViewerMessage,
  type ViewerMessageHandlerMap,
} from '../../utils/messageRouterUtils';

suite('messageRouterUtils', () => {
  test('routes each supported message type to the matching handler', async () => {
    const calls: string[] = [];
    const handlers: ViewerMessageHandlerMap = {
      copyToClipboard: async () => { calls.push('copyToClipboard'); },
      passphraseResponse: async () => { calls.push('passphraseResponse'); },
      inputDialogResponse: async () => { calls.push('inputDialogResponse'); },
      downloadCaIssuer: async () => { calls.push('downloadCaIssuer'); },
      openCaCertFile: async () => { calls.push('openCaCertFile'); },
      exportCert: async () => { calls.push('exportCert'); },
      exportPrivateKey: async () => { calls.push('exportPrivateKey'); },
      importPrivateKey: async () => { calls.push('importPrivateKey'); },
      createP12: async () => { calls.push('createP12'); },
      signCsr: async () => { calls.push('signCsr'); },
      savePrivateKey: async () => { calls.push('savePrivateKey'); },
      saveCsrFile: async () => { calls.push('saveCsrFile'); },
      saveBothFiles: async () => { calls.push('saveBothFiles'); },
      openConvertHub: async () => { calls.push('openConvertHub'); },
    };

    const messages: Array<{ type: string; msg: WebviewToExtMsg }> = [
      { type: 'copyToClipboard', msg: { type: 'copyToClipboard', value: 'x' } as WebviewToExtMsg },
      { type: 'passphraseResponse', msg: { type: 'passphraseResponse', requestId: '1', passphrase: 'pw' } as WebviewToExtMsg },
      { type: 'inputDialogResponse', msg: { type: 'inputDialogResponse', requestId: '2', values: { name: 'a' } } as WebviewToExtMsg },
      { type: 'downloadCaIssuer', msg: { type: 'downloadCaIssuer', url: 'https://example.test/ca.cer' } as WebviewToExtMsg },
      { type: 'openCaCertFile', msg: { type: 'openCaCertFile', topCertPem: 'pem' } as WebviewToExtMsg },
      { type: 'exportCert', msg: { type: 'exportCert', pem: 'pem', suggestedName: 'cert.pem', format: 'pem' } as WebviewToExtMsg },
      { type: 'exportPrivateKey', msg: { type: 'exportPrivateKey', keyPem: 'key', suggestedName: 'key.pem' } as WebviewToExtMsg },
      { type: 'importPrivateKey', msg: { type: 'importPrivateKey', certIndex: 0, spkiPem: 'spki' } as WebviewToExtMsg },
      { type: 'createP12', msg: { type: 'createP12', certPems: ['pem'], suggestedName: 'bundle.p12' } as WebviewToExtMsg },
      { type: 'signCsr', msg: { type: 'signCsr', csrPem: 'csr' } as WebviewToExtMsg },
      { type: 'savePrivateKey', msg: { type: 'savePrivateKey' } as WebviewToExtMsg },
      { type: 'saveCsrFile', msg: { type: 'saveCsrFile' } as WebviewToExtMsg },
      { type: 'saveBothFiles', msg: { type: 'saveBothFiles', suggestedName: 'cert' } as WebviewToExtMsg },
      { type: 'openConvertHub', msg: { type: 'openConvertHub' } as WebviewToExtMsg },
    ];

    for (const { msg } of messages) {
      await routeViewerMessage(msg, handlers);
    }

    assert.deepStrictEqual(calls, messages.map(message => message.type));
  });

  test('ignores unsupported message types', async () => {
    let called = false;
    const handlers: ViewerMessageHandlerMap = {
      copyToClipboard: async () => { called = true; },
      passphraseResponse: async () => { called = true; },
      inputDialogResponse: async () => { called = true; },
      downloadCaIssuer: async () => { called = true; },
      openCaCertFile: async () => { called = true; },
      exportCert: async () => { called = true; },
      exportPrivateKey: async () => { called = true; },
      importPrivateKey: async () => { called = true; },
      createP12: async () => { called = true; },
      signCsr: async () => { called = true; },
      savePrivateKey: async () => { called = true; },
      saveCsrFile: async () => { called = true; },
      saveBothFiles: async () => { called = true; },
      openConvertHub: async () => { called = true; },
    };

    await routeViewerMessage({ type: 'unsupported' } as unknown as WebviewToExtMsg, handlers);
    assert.strictEqual(called, false);
  });
});
