import * as vscode from 'vscode';
import * as assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import sinon from 'sinon';
import {
  getOrCreatePanel,
  sendLoading,
  sendCertificates,
  sendCsr,
  sendError,
  handleWebviewMessage,
  requestPassphraseFromWebview,
  requestInputDialogFromWebview,
} from '../../panels/mainViewerPanel';
import type { CertificateData, CsrData, ExtToWebviewMsg, WebviewToExtMsg, DistinguishedName, TlsConnectionInfo } from '@x509-toolkit/core';

function mockExtensionUri(): vscode.Uri {
  return vscode.Uri.file(path.resolve(__dirname, '../../..'));
}

function mockContext(): vscode.ExtensionContext {
  return { subscriptions: [] } as unknown as vscode.ExtensionContext;
}

function sampleDN(): DistinguishedName {
  return { raw: 'CN=test.example.com' };
}

function sampleCertData(): CertificateData {
  return {
    version: 3,
    serialNumber: '01',
    subject: sampleDN(),
    issuer: sampleDN(),
    validity: {
      notBefore: '2024-01-01T00:00:00Z',
      notAfter: '2025-01-01T00:00:00Z',
      isExpired: false,
      daysRemaining: 365,
    },
    publicKey: {
      algorithm: 'RSA',
      keySize: 2048,
      spki: '00:11:22:33',
      spkiPem: '-----BEGIN PUBLIC KEY-----\nMIIB...',
    },
    signature: { algorithm: 'SHA256-RSA', value: 'AA:BB:CC' },
    extensions: [],
    fingerprints: { sha1: 'AA:BB:CC:DD', sha256: '11:22:33:44' },
    raw: '-----BEGIN CERTIFICATE-----\nMIIF...',
    isCA: false,
    isSelfSigned: false,
  };
}

function sampleCsrData(): CsrData {
  return {
    subject: sampleDN(),
    publicKey: {
      algorithm: 'RSA',
      keySize: 2048,
      spki: '00:11:22:33',
      spkiPem: '-----BEGIN PUBLIC KEY-----\nMIIB...',
    },
    signatureAlgorithm: 'SHA256-RSA',
    extensions: [],
    raw: '-----BEGIN CERTIFICATE REQUEST-----\nMIIC...',
  };
}

suite('mainViewerPanel', () => {
  let panel: vscode.WebviewPanel;
  let postMessageSpy: sinon.SinonSpy;

  setup(function () {
    panel = getOrCreatePanel(mockExtensionUri(), mockContext());
    postMessageSpy = sinon.spy(panel.webview, 'postMessage');
  });

  teardown(function () {
    sinon.restore();
    panel?.dispose();
  });

  // -----------------------------------------------------------------------
  // Panel lifecycle
  // -----------------------------------------------------------------------
  suite('getOrCreatePanel', () => {
    test('creates panel with correct view type and title', () => {
      assert.strictEqual(panel.viewType, 'x509toolkit');
      assert.ok(panel.title.includes('X.509'));
    });

    test('enables scripts', () => {
      assert.ok(panel.webview.options?.enableScripts);
    });

    test('sets localResourceRoots to dist/webview', () => {
      const roots = panel.webview.options?.localResourceRoots ?? [];
      assert.ok(roots.length > 0);
      assert.ok(roots.some(r => r.path.replace(/\\/g, '/').includes('dist/webview')));
    });

    test('returns the same panel on subsequent calls', () => {
      const panel2 = getOrCreatePanel(mockExtensionUri(), mockContext());
      assert.strictEqual(panel, panel2);
    });

    test('generates HTML with script and style tags', () => {
      const html = panel.webview.html;
      assert.ok(html.includes('<script'), 'HTML should contain a script tag');
      assert.ok(html.includes('<link'), 'HTML should contain a link tag for CSS');
      assert.ok(html.includes('nonce='), 'HTML should contain CSP nonce');
      assert.ok(html.includes('default-src'), 'HTML should contain CSP header');
    });
  });

  // -----------------------------------------------------------------------
  // Extension → Webview message protocol
  // -----------------------------------------------------------------------
  suite('send functions (extension → webview messages)', () => {
    test('sendLoading posts { type: "loading" }', () => {
      sendLoading(panel);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'loading' }));
    });

    test('sendLoading with status includes status field', () => {
      sendLoading(panel, 'Parsing certificate...');
      assert.ok(postMessageSpy.calledWithMatch({ type: 'loading', status: 'Parsing certificate...' }));
    });

    test('sendError posts error message', () => {
      sendError(panel, 'Failed to parse file');
      assert.ok(postMessageSpy.calledWithMatch({ type: 'error', message: 'Failed to parse file' }));
    });

    test('sendCertificates posts chain and activeIndex', () => {
      const chain = [sampleCertData()];
      sendCertificates(panel, chain, 0);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'certificate', activeIndex: 0 }));
    });

    test('sendCertificates with tlsSource includes connection info', () => {
      const chain = [sampleCertData()];
      const tlsSource: TlsConnectionInfo = {
        host: 'example.com',
        port: 443,
        ip: '93.184.216.34',
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_256_GCM_SHA384',
        steps: ['connected', 'handshake', 'secure'],
      };
      sendCertificates(panel, chain, 0, tlsSource);
      assert.ok(postMessageSpy.calledWithMatch({
        type: 'certificate',
        tlsSource: { host: 'example.com', port: 443 },
      }));
    });

    test('sendCsr posts CSR data', () => {
      const data = sampleCsrData();
      sendCsr(panel, data);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'csr', data }));
    });

    test('sendCsr with private key adds description', () => {
      const data = sampleCsrData();
      sendCsr(panel, data, '-----BEGIN RSA PRIVATE KEY-----\n...');
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'csr' };
      assert.strictEqual(msg.type, 'csr');
      assert.ok(typeof msg.data.privateKeyDescription === 'string');
    });
  });

  // -----------------------------------------------------------------------
  // Webview → Extension message dispatch
  // -----------------------------------------------------------------------
  suite('handleWebviewMessage dispatch', () => {
    test('copyToClipboard writes value to clipboard', async () => {
      await handleWebviewMessage(panel, { type: 'copyToClipboard', value: 'hello-test' });
      const clipboard = await vscode.env.clipboard.readText();
      assert.strictEqual(clipboard, 'hello-test');
    });

    test('passphraseResponse resolves pending passphrase request', async () => {
      const promise = requestPassphraseFromWebview(panel, 'test.p12');
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestPassphrase' };
      await handleWebviewMessage(panel, {
        type: 'passphraseResponse',
        requestId: msg.requestId,
        passphrase: 'supersecret',
      });
      const result = await promise;
      assert.strictEqual(result, 'supersecret');
    });

    test('passphraseResponse with null cancels the request', async () => {
      const promise = requestPassphraseFromWebview(panel, 'test.p12');
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestPassphrase' };
      await handleWebviewMessage(panel, {
        type: 'passphraseResponse',
        requestId: msg.requestId,
        passphrase: null,
      });
      const result = await promise;
      assert.strictEqual(result, null);
    });

    test('inputDialogResponse resolves pending input dialog request', async () => {
      const fields = [{ id: 'name', label: 'Name', type: 'text' as const }];
      const promise = requestInputDialogFromWebview(panel, 'Enter Name', fields);
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestInputDialog' };
      await handleWebviewMessage(panel, {
        type: 'inputDialogResponse',
        requestId: msg.requestId,
        values: { name: 'Alice' },
      });
      const result = await promise;
      assert.deepStrictEqual(result, { name: 'Alice' });
    });

    test('inputDialogResponse with null cancels the dialog', async () => {
      const fields = [{ id: 'name', label: 'Name', type: 'text' as const }];
      const promise = requestInputDialogFromWebview(panel, 'Enter Name', fields);
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestInputDialog' };
      await handleWebviewMessage(panel, {
        type: 'inputDialogResponse',
        requestId: msg.requestId,
        values: null,
      });
      const result = await promise;
      assert.strictEqual(result, null);
    });

    test('unknown message type does not throw', async () => {
      await handleWebviewMessage(panel, { type: 'copyToClipboard' as any, value: 'x' });
    });
  });

  // -----------------------------------------------------------------------
  // Request-response bridges
  // -----------------------------------------------------------------------
  suite('request dialogs (extension → webview → extension)', () => {
    test('requestPassphraseFromWebview posts requestPassphrase message', async () => {
      requestPassphraseFromWebview(panel, 'mykey.pem');
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestPassphrase' };
      assert.strictEqual(msg.type, 'requestPassphrase');
      assert.strictEqual(msg.fileName, 'mykey.pem');
      assert.ok(msg.requestId, 'should generate a requestId');
    });

    test('requestPassphraseFromWebview forwards options', () => {
      requestPassphraseFromWebview(panel, 'key.pem', {
        title: 'Unlock Key',
        description: 'Enter passphrase',
        requireConfirm: true,
      });
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestPassphrase' };
      assert.strictEqual(msg.title, 'Unlock Key');
      assert.strictEqual(msg.description, 'Enter passphrase');
      assert.strictEqual(msg.requireConfirm, true);
    });

    test('requestInputDialogFromWebview posts requestInputDialog message', () => {
      const fields = [{ id: 'days', label: 'Days', type: 'number' as const }];
      requestInputDialogFromWebview(panel, 'Validity', fields, { icon: '📅' });
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestInputDialog' };
      assert.strictEqual(msg.type, 'requestInputDialog');
      assert.strictEqual(msg.title, 'Validity');
      assert.strictEqual(msg.fields.length, 1);
      assert.strictEqual(msg.icon, '📅');
    });
  });

  // -----------------------------------------------------------------------
  // Handlers that involve VS Code dialogs (mocked with sinon)
  // -----------------------------------------------------------------------
  suite('handlers with mocked VS Code dialogs', () => {
    let tmpDir: string;

    setup(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x509-test-'));
    });

    teardown(() => {
      sinon.restore();
      if (tmpDir) {
        fs.rmSync(tmpDir, { recursive: true, force: true });
      }
    });

    test('handleExportCert saves PEM file via showSaveDialog', async () => {
      const savePath = path.join(tmpDir, 'exported.pem');
      sinon.stub(vscode.window, 'showSaveDialog').resolves(vscode.Uri.file(savePath));
      postMessageSpy.resetHistory();

      const msg: WebviewToExtMsg = {
        type: 'exportCert',
        pem: '-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----',
        suggestedName: 'cert.pem',
        format: 'pem',
      };

      await handleWebviewMessage(panel, msg);

      const opts = (vscode.window.showSaveDialog as sinon.SinonStub).firstCall.args[0];
      assert.ok(opts?.defaultUri?.path.includes('cert.pem'));
      assert.strictEqual(opts?.saveLabel, 'Export Certificate');

      assert.ok(fs.existsSync(savePath), 'file should have been written');
      const content = fs.readFileSync(savePath, 'utf-8');
      assert.ok(content.includes('BEGIN CERTIFICATE'));
    });

    test('handleExportCert saves DER file', async () => {
      const savePath = path.join(tmpDir, 'cert.der');
      sinon.stub(vscode.window, 'showSaveDialog').resolves(vscode.Uri.file(savePath));

      const b64Content = Buffer.from('test-der-data').toString('base64');
      const pem = '-----BEGIN CERTIFICATE-----\n' + b64Content + '\n-----END CERTIFICATE-----';
      const msg: WebviewToExtMsg = {
        type: 'exportCert',
        pem,
        suggestedName: 'cert.der',
        format: 'der',
      };

      await handleWebviewMessage(panel, msg);

      const filters = (vscode.window.showSaveDialog as sinon.SinonStub).firstCall.args[0]?.filters;
      assert.ok(filters?.['DER Certificate']);

      assert.ok(fs.existsSync(savePath));
    });

    test('handleExportCert cancels when dialog returns undefined', async () => {
      sinon.stub(vscode.window, 'showSaveDialog').resolves(undefined);
      postMessageSpy.resetHistory();

      const msg: WebviewToExtMsg = {
        type: 'exportCert',
        pem: '-----BEGIN CERTIFICATE-----\nMIIF...',
        suggestedName: 'cert.pem',
        format: 'pem',
      };

      await handleWebviewMessage(panel, msg);
      assert.ok(!postMessageSpy.called, 'no message should be posted on cancel');
    });

    test('handleExportPrivateKey saves key file', async () => {
      const savePath = path.join(tmpDir, 'key.pem');
      sinon.stub(vscode.window, 'showSaveDialog').resolves(vscode.Uri.file(savePath));

      const msg: WebviewToExtMsg = {
        type: 'exportPrivateKey',
        keyPem: '-----BEGIN PRIVATE KEY-----\nMIIF...',
        suggestedName: 'private.key',
      };

      await handleWebviewMessage(panel, msg);

      assert.ok(fs.existsSync(savePath));
      const content = fs.readFileSync(savePath, 'utf-8');
      assert.ok(content.includes('BEGIN PRIVATE KEY'));
    });
  });
});
