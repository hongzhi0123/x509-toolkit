import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import sinon from 'sinon';
import { createSelfSignedP12 } from '@x509-toolkit/core';
import type { ExtToWebviewMsg } from '@x509-toolkit/core';
import { openFile } from '../../../commands/openFile';
import { getOrCreatePanel, handleWebviewMessage } from '../../../panels/mainViewerPanel';
import { findPostedMessage, mockContext, mockExtensionUri, waitForPostedMessage } from './helpers/workflowTestUtils';

type RequestPassphraseMsg = ExtToWebviewMsg & { type: 'requestPassphrase'; requestId: string };
type CertificateMsg = ExtToWebviewMsg & { type: 'certificate'; chain: Array<{ subject: { commonName?: string } }> };
type ErrorMsg = ExtToWebviewMsg & { type: 'error'; message: string };

async function waitForPassphraseRequestWithReadyPings(
  panel: vscode.WebviewPanel,
  postMessageSpy: sinon.SinonSpy,
): Promise<RequestPassphraseMsg> {
  const timeoutMs = 12_000;
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    await handleWebviewMessage(panel, { type: 'ready' });
    const request = findPostedMessage<RequestPassphraseMsg>(postMessageSpy, 'requestPassphrase');
    if (request) {
      return request;
    }
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  throw new Error('Timed out waiting for passphrase request.');
}

suite('e2e: open file workflow', () => {
  let tmpDir: string;
  let panel: vscode.WebviewPanel;

  setup(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x509-e2e-'));
    panel = getOrCreatePanel(mockExtensionUri(), mockContext());
  });

  teardown(() => {
    sinon.restore();
    panel.dispose();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('opens encrypted P12 through command, prompts passphrase, and renders certificate', async () => {
    const postMessageSpy = sinon.spy(panel.webview, 'postMessage');
    const p12Path = path.join(tmpDir, 'flow.p12');
    const password = 'e2e-pass';
    const p12 = await createSelfSignedP12('E2E Flow', 30, password);
    fs.writeFileSync(p12Path, p12);

    sinon.stub(vscode.window, 'showOpenDialog').resolves([vscode.Uri.file(p12Path)]);

    const runOpenFile = openFile(mockContext())();
    const passphraseRequest = await waitForPassphraseRequestWithReadyPings(panel, postMessageSpy);
    await handleWebviewMessage(panel, {
      type: 'passphraseResponse',
      requestId: passphraseRequest.requestId,
      passphrase: password,
    });

    await runOpenFile;

    const certMsg = await waitForPostedMessage<CertificateMsg>(postMessageSpy, 'certificate');
    assert.ok(certMsg.chain.length > 0, 'certificate chain should be populated');
    assert.strictEqual(certMsg.chain[0].subject.commonName, 'E2E Flow');
  });

  test('shows an error when wrong passphrase is submitted', async () => {
    const postMessageSpy = sinon.spy(panel.webview, 'postMessage');
    const p12Path = path.join(tmpDir, 'wrong-pass.p12');
    const p12 = await createSelfSignedP12('Wrong Pass', 30, 'correct-pass');
    fs.writeFileSync(p12Path, p12);

    sinon.stub(vscode.window, 'showOpenDialog').resolves([vscode.Uri.file(p12Path)]);

    const runOpenFile = openFile(mockContext())();
    const passphraseRequest = await waitForPassphraseRequestWithReadyPings(panel, postMessageSpy);
    await handleWebviewMessage(panel, {
      type: 'passphraseResponse',
      requestId: passphraseRequest.requestId,
      passphrase: 'wrong-pass',
    });

    await runOpenFile;

    const errorMsg = await waitForPostedMessage<ErrorMsg>(postMessageSpy, 'error');
    assert.match(errorMsg.message, /password|corrupted|failed to parse/i);
  });
});
