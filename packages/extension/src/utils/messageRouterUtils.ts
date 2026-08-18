import type { WebviewToExtMsg } from '@x509-toolkit/core';

export type ViewerMessageHandlerMap = {
  copyToClipboard: (msg: Extract<WebviewToExtMsg, { type: 'copyToClipboard' }>) => Promise<void> | void;
  passphraseResponse: (msg: Extract<WebviewToExtMsg, { type: 'passphraseResponse' }>) => Promise<void> | void;
  inputDialogResponse: (msg: Extract<WebviewToExtMsg, { type: 'inputDialogResponse' }>) => Promise<void> | void;
  downloadCaIssuer: (msg: Extract<WebviewToExtMsg, { type: 'downloadCaIssuer' }>) => Promise<void> | void;
  openCaCertFile: (msg: Extract<WebviewToExtMsg, { type: 'openCaCertFile' }>) => Promise<void> | void;
  exportCert: (msg: Extract<WebviewToExtMsg, { type: 'exportCert' }>) => Promise<void> | void;
  exportPrivateKey: (msg: Extract<WebviewToExtMsg, { type: 'exportPrivateKey' }>) => Promise<void> | void;
  importPrivateKey: (msg: Extract<WebviewToExtMsg, { type: 'importPrivateKey' }>) => Promise<void> | void;
  createP12: (msg: Extract<WebviewToExtMsg, { type: 'createP12' }>) => Promise<void> | void;
  signCsr: (msg: Extract<WebviewToExtMsg, { type: 'signCsr' }>) => Promise<void> | void;
  savePrivateKey: (msg: Extract<WebviewToExtMsg, { type: 'savePrivateKey' }>) => Promise<void> | void;
  saveCsrFile: (msg: Extract<WebviewToExtMsg, { type: 'saveCsrFile' }>) => Promise<void> | void;
  saveBothFiles: (msg: Extract<WebviewToExtMsg, { type: 'saveBothFiles' }>) => Promise<void> | void;
  openConvertHub: (msg: Extract<WebviewToExtMsg, { type: 'openConvertHub' }>) => Promise<void> | void;
};

export async function routeViewerMessage(
  msg: WebviewToExtMsg,
  handlers: ViewerMessageHandlerMap
): Promise<void> {
  switch (msg.type) {
    case 'copyToClipboard': return handlers.copyToClipboard(msg);
    case 'passphraseResponse': return handlers.passphraseResponse(msg);
    case 'inputDialogResponse': return handlers.inputDialogResponse(msg);
    case 'downloadCaIssuer': return handlers.downloadCaIssuer(msg);
    case 'openCaCertFile': return handlers.openCaCertFile(msg);
    case 'exportCert': return handlers.exportCert(msg);
    case 'exportPrivateKey': return handlers.exportPrivateKey(msg);
    case 'importPrivateKey': return handlers.importPrivateKey(msg);
    case 'createP12': return handlers.createP12(msg);
    case 'signCsr': return handlers.signCsr(msg);
    case 'savePrivateKey': return handlers.savePrivateKey(msg);
    case 'saveCsrFile': return handlers.saveCsrFile(msg);
    case 'saveBothFiles': return handlers.saveBothFiles(msg);
    case 'openConvertHub': return handlers.openConvertHub(msg);
  }
}
