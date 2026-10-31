import * as vscode from 'vscode';
import * as assert from 'assert';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as http from 'http';
import sinon from 'sinon';
import { createSelfSignedP12, parseP12 } from '@x509-toolkit/core';
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
  return {
    subscriptions: [],
    extensionUri: mockExtensionUri(),
  } as unknown as vscode.ExtensionContext;
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

async function flushViewerQueue(panel: vscode.WebviewPanel): Promise<void> {
  await handleWebviewMessage(panel, { type: 'ready' });
}

function pemCertificateToDer(pem: string): Buffer {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}

async function waitForPostedMessage(
  spy: sinon.SinonSpy,
  type: string,
  timeoutMs = 2_000
): Promise<Record<string, unknown>> {
  const start = Date.now();

  while (Date.now() - start < timeoutMs) {
    for (let i = 0; i < spy.callCount; i++) {
      const message = spy.getCall(i).args[0] as Record<string, unknown>;
      if (message?.type === type) {
        return message;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  throw new Error(`Timed out waiting for webview message type: ${type}`);
}

suite('mainViewerPanel', () => {
  let panel: vscode.WebviewPanel;
  let postMessageSpy: sinon.SinonSpy;
  let fixtureCertPem: string;
  let fixtureCertDer: Buffer;
  let fixtureSpkiPem: string;
  let fixtureKeyPem: string;

  suiteSetup(async () => {
    const p12 = await createSelfSignedP12('main-viewer-handler.example', 30, 'test-password');
    const certs = await parseP12(p12, 'test-password');
    const cert = certs[0];
    fixtureCertPem = cert.raw;
    fixtureCertDer = pemCertificateToDer(cert.raw);
    fixtureSpkiPem = cert.publicKey.spkiPem;
    if (!cert.privateKey?.pem) {
      throw new Error('Expected parseP12 fixture certificate to include a private key.');
    }
    fixtureKeyPem = cert.privateKey.pem;
  });

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
    test('sendLoading posts { type: "loading" }', async () => {
      sendLoading(panel);
      await flushViewerQueue(panel);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'loading' }));
    });

    test('sendLoading with status includes status field', async () => {
      sendLoading(panel, 'Parsing certificate...');
      await flushViewerQueue(panel);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'loading', status: 'Parsing certificate...' }));
    });

    test('sendError posts error message', async () => {
      sendError(panel, 'Failed to parse file');
      await flushViewerQueue(panel);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'error', message: 'Failed to parse file' }));
    });

    test('sendCertificates posts chain and activeIndex', async () => {
      const chain = [sampleCertData()];
      sendCertificates(panel, chain, 0);
      await flushViewerQueue(panel);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'certificate', activeIndex: 0 }));
    });

    test('sendCertificates with tlsSource includes connection info', async () => {
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
      await flushViewerQueue(panel);
      assert.ok(postMessageSpy.calledWithMatch({
        type: 'certificate',
        tlsSource: { host: 'example.com', port: 443 },
      }));
    });

    test('sendCsr posts CSR data', async () => {
      const data = sampleCsrData();
      sendCsr(panel, data);
      await flushViewerQueue(panel);
      assert.ok(postMessageSpy.calledWithMatch({ type: 'csr', data }));
    });

    test('sendCsr with private key adds description', async () => {
      const data = sampleCsrData();
      sendCsr(panel, data, '-----BEGIN RSA PRIVATE KEY-----\n...');
      await flushViewerQueue(panel);
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
      await flushViewerQueue(panel);
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
      await flushViewerQueue(panel);
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
      await flushViewerQueue(panel);
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
      await flushViewerQueue(panel);
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
      await flushViewerQueue(panel);
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestPassphrase' };
      assert.strictEqual(msg.type, 'requestPassphrase');
      assert.strictEqual(msg.fileName, 'mykey.pem');
      assert.ok(msg.requestId, 'should generate a requestId');
    });

    test('requestPassphraseFromWebview forwards options', async () => {
      requestPassphraseFromWebview(panel, 'key.pem', {
        title: 'Unlock Key',
        description: 'Enter passphrase',
        requireConfirm: true,
      });
      await flushViewerQueue(panel);
      const msg = postMessageSpy.firstCall.args[0] as ExtToWebviewMsg & { type: 'requestPassphrase' };
      assert.strictEqual(msg.title, 'Unlock Key');
      assert.strictEqual(msg.description, 'Enter passphrase');
      assert.strictEqual(msg.requireConfirm, true);
    });

    test('requestInputDialogFromWebview posts requestInputDialog message', async () => {
      const fields = [{ id: 'days', label: 'Days', type: 'number' as const }];
      requestInputDialogFromWebview(panel, 'Validity', fields, { icon: '📅' });
      await flushViewerQueue(panel);
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

    test('handleDownloadCaIssuer posts CA issuer certificate on successful fetch', async () => {
      postMessageSpy.resetHistory();
      const server = http.createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/pkix-cert' });
        res.end(fixtureCertDer);
      });

      const port = await new Promise<number>((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
          const address = server.address();
          if (!address || typeof address === 'string') {
            reject(new Error('Failed to acquire HTTP test server port.'));
            return;
          }
          resolve(address.port);
        });
      });

      const url = `http://127.0.0.1:${port}/issuer.der`;
      try {
        await handleWebviewMessage(panel, { type: 'downloadCaIssuer', url });
        const message = await waitForPostedMessage(postMessageSpy, 'caIssuerCert');
        assert.strictEqual(message.type, 'caIssuerCert');
        assert.strictEqual(message.url, url);
        const cert = message.cert as { subject?: { commonName?: string } };
        assert.ok(cert?.subject?.commonName, 'expected parsed certificate payload');
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    });

    test('handleDownloadCaIssuer posts error when URL is unsupported', async () => {
      postMessageSpy.resetHistory();
      const url = 'ftp://invalid.example/issuer.der';

      await handleWebviewMessage(panel, { type: 'downloadCaIssuer', url });
      const message = await waitForPostedMessage(postMessageSpy, 'caIssuerError');

      assert.strictEqual(message.type, 'caIssuerError');
      assert.strictEqual(message.url, url);
      assert.match(String(message.message ?? ''), /Only http:\/\/ and https:\/\//i);
    });

    test('handleImportPrivateKey imports matching key and posts privateKeyImported', async () => {
      postMessageSpy.resetHistory();
      const keyPath = path.join(tmpDir, 'matching.key');
      fs.writeFileSync(keyPath, fixtureKeyPem, 'utf8');
      sinon.stub(vscode.window, 'showOpenDialog').resolves([vscode.Uri.file(keyPath)]);

      await handleWebviewMessage(panel, {
        type: 'importPrivateKey',
        certIndex: 2,
        spkiPem: fixtureSpkiPem,
      });

      const message = await waitForPostedMessage(postMessageSpy, 'privateKeyImported');
      assert.strictEqual(message.type, 'privateKeyImported');
      assert.strictEqual(message.certIndex, 2);
      const key = message.key as { algorithm?: string; pem?: string };
      assert.ok(typeof key.algorithm === 'string' && key.algorithm.length > 0);
      assert.ok(typeof key.pem === 'string' && key.pem.includes('BEGIN PRIVATE KEY'));
    });

    test('handleCreateP12 creates and saves P12 when key is provided', async () => {
      await flushViewerQueue(panel);
      postMessageSpy.resetHistory();

      const savePath = path.join(tmpDir, 'created-with-key.p12');
      sinon.stub(vscode.window, 'showSaveDialog').resolves(vscode.Uri.file(savePath));
      const infoSpy = sinon.spy(vscode.window, 'showInformationMessage');

      const createPromise = handleWebviewMessage(panel, {
        type: 'createP12',
        certPems: [fixtureCertPem],
        suggestedName: 'created-with-key.p12',
        keyPem: fixtureKeyPem,
      });

      const prompt = await waitForPostedMessage(postMessageSpy, 'requestPassphrase');
      await handleWebviewMessage(panel, {
        type: 'passphraseResponse',
        requestId: String(prompt.requestId),
        passphrase: 'export-password',
      });

      await createPromise;

      assert.ok(fs.existsSync(savePath), 'expected P12 output file to be created');
      const stat = fs.statSync(savePath);
      assert.ok(stat.size > 0, 'expected non-empty P12 output');
      assert.ok(infoSpy.calledWithMatch(sinon.match(/with private key/i)));
    });

    test('handleOpenConvertHub opens the conversion panel', async () => {
      const createPanelSpy = sinon.spy(vscode.window, 'createWebviewPanel');

      await handleWebviewMessage(panel, { type: 'openConvertHub' });

      assert.ok(createPanelSpy.calledOnce);
      assert.strictEqual(createPanelSpy.firstCall.args[0], 'x509ConvertHub');

      const convertPanel = createPanelSpy.firstCall.returnValue as vscode.WebviewPanel;
      convertPanel.dispose();
    });
  });
});
