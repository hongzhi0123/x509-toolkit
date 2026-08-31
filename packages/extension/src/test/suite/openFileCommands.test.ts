import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as vscode from 'vscode';
import sinon from 'sinon';
import {
  createSelfSignedP12,
  generateCsr,
  generateKeyPair,
  parseP12,
  type CertCreateParams,
  type ExtToCrlViewerMsg,
  type ExtToKeyViewerMsg,
  type ExtToWebviewMsg,
} from '@x509-toolkit/core';
import {
  BasicConstraintsExtension,
  SubjectKeyIdentifierExtension,
  X509CertificateGenerator,
  X509CrlGenerator,
  cryptoProvider,
} from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import { openFile } from '../../commands/openFile';
import { openFromExplorer } from '../../commands/openFromExplorer';

type PostedMessage = ExtToWebviewMsg | ExtToCrlViewerMsg | ExtToKeyViewerMsg;

type FakePanel = vscode.WebviewPanel & {
  postedMessages: PostedMessage[];
  fireMessage: (msg: unknown) => Promise<void>;
};

function mockContext(): vscode.ExtensionContext {
  return {
    subscriptions: [],
    extensionUri: vscode.Uri.file('d:/Dev/ai/x509-viewer/x509-toolkit/packages/extension'),
  } as unknown as vscode.ExtensionContext;
}

function makeParams(overrides?: Partial<CertCreateParams>): CertCreateParams {
  return {
    cn: 'command-route.example',
    o: 'Test Org',
    ou: 'Extension Tests',
    c: 'US',
    st: 'California',
    l: 'San Jose',
    email: 'test@example.com',
    dnsNames: '',
    ipAddresses: '',
    keyAlgorithm: 'RSA-2048',
    validityDays: 30,
    isCA: false,
    keyUsageDigitalSignature: true,
    keyUsageKeyEncipherment: true,
    keyUsageDataEncipherment: false,
    keyUsageKeyCertSign: false,
    keyUsageCRLSign: false,
    ekuServerAuth: true,
    ekuClientAuth: false,
    ekuCodeSigning: false,
    ekuEmailProtection: false,
    signingMode: 'self-signed',
    password: 'test-password',
    ...overrides,
  };
}

function pemCertificateToDer(pem: string): Buffer {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}

function createFakePanel(viewType: string, title: string, options?: vscode.WebviewOptions): FakePanel {
  const postedMessages: PostedMessage[] = [];
  let receiveMessageHandler: ((msg: unknown) => unknown | Promise<unknown>) | undefined;
  let disposeHandler: (() => void) | undefined;

  const webview = {
    html: '',
    options,
    cspSource: 'vscode-webview-resource:',
    asWebviewUri: (uri: vscode.Uri) => uri,
    postMessage: async (msg: PostedMessage) => {
      postedMessages.push(msg);
      return true;
    },
    onDidReceiveMessage: (handler: (msg: unknown) => unknown | Promise<unknown>) => {
      receiveMessageHandler = handler;
      return { dispose() {} } as vscode.Disposable;
    },
  } as unknown as vscode.Webview;

  return {
    viewType,
    title,
    webview,
    postedMessages,
    options: { enableFindWidget: false, retainContextWhenHidden: true },
    viewColumn: vscode.ViewColumn.Two,
    visible: true,
    active: true,
    reveal() {},
    dispose() {
      disposeHandler?.();
    },
    onDidDispose: (handler: () => void) => {
      disposeHandler = handler;
      return { dispose() {} } as vscode.Disposable;
    },
    iconPath: undefined,
    busy: false,
    badge: undefined,
    activeViewColumn: vscode.ViewColumn.Two,
    fireMessage: async (msg: unknown) => {
      if (receiveMessageHandler) {
        await receiveMessageHandler(msg);
      }
    },
  } as unknown as FakePanel;
}

function findPostedMessage<T extends { type: string }>(panel: FakePanel, type: T['type']): T | undefined {
  return panel.postedMessages.find((msg) => msg.type === type) as T | undefined;
}

suite('openFile and openFromExplorer commands', () => {
  const webcrypto = new PeculiarCrypto();
  let tmpDir: string;
  let crlPath: string;
  let csrPath: string;
  let derCertPath: string;
  let keyPath: string;
  let unsupportedPath: string;
  let createdPanels: FakePanel[];
  let createWebviewPanelStub: sinon.SinonStub;

  suiteSetup(async () => {
    cryptoProvider.set(webcrypto);
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'x509-open-routes-'));

    const p12Buffer = await createSelfSignedP12('command-route-cert', 30, 'test-password');
    const [certificate] = await parseP12(p12Buffer, 'test-password');
    derCertPath = path.join(tmpDir, 'leaf.der');
    fs.writeFileSync(derCertPath, pemCertificateToDer(certificate.raw));

    const csr = await generateCsr(makeParams({ cn: 'command-route-csr' }));
    csrPath = path.join(tmpDir, 'request.csr');
    fs.writeFileSync(csrPath, csr.csrPem, 'utf8');

    const keyPair = await generateKeyPair('RSA-2048');
    keyPath = path.join(tmpDir, 'private.key');
    fs.writeFileSync(keyPath, keyPair.privateKeyPem, 'utf8');

    const caKeys = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const caCert = await X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=CRL Route Test, O=Test Org, C=US',
      notBefore: new Date('2024-01-01T00:00:00Z'),
      notAfter: new Date('2035-01-01T00:00:00Z'),
      keys: caKeys,
      signingAlgorithm: { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as any,
      extensions: [
        new BasicConstraintsExtension(true, undefined, true),
        await SubjectKeyIdentifierExtension.create(caKeys.publicKey, false, webcrypto),
      ],
    });
    const crl = await X509CrlGenerator.create({
      issuer: caCert.issuer,
      thisUpdate: new Date('2024-01-15T00:00:00Z'),
      nextUpdate: new Date('2035-01-15T00:00:00Z'),
      entries: [],
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } as any,
      signingKey: caKeys.privateKey,
    }, webcrypto);
    crlPath = path.join(tmpDir, 'revocation-list.crl');
    fs.writeFileSync(crlPath, crl.toString('pem'), 'utf8');

    unsupportedPath = path.join(tmpDir, 'dummy.txt');
    fs.writeFileSync(unsupportedPath, 'not a certificate', 'utf8');
  });

  setup(() => {
    createdPanels = [];
    createWebviewPanelStub = sinon.stub(vscode.window, 'createWebviewPanel').callsFake((viewType, title, _showOptions, options) => {
      const panel = createFakePanel(viewType, title, options);
      createdPanels.push(panel);
      return panel;
    });
  });

  teardown(() => {
    for (const panel of createdPanels) {
      panel.dispose();
    }
    sinon.restore();
  });

  suiteTeardown(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('openFile routes a CRL file to the CRL viewer', async () => {
    sinon.stub(vscode.window, 'showOpenDialog').resolves([vscode.Uri.file(crlPath)]);

    await openFile(mockContext())();

    assert.strictEqual(createWebviewPanelStub.firstCall.args[0], 'x509CrlViewer');
    const panel = createdPanels[0];
    await panel.fireMessage({ type: 'crlViewerReady' });

    assert.ok(findPostedMessage<ExtToCrlViewerMsg & { type: 'crlLoading' }>(panel, 'crlLoading'));
    const msg = findPostedMessage<ExtToCrlViewerMsg & { type: 'crlData'; crl: { sourceFormat?: string } }>(panel, 'crlData');
    assert.ok(msg);
    assert.strictEqual(msg?.crl.sourceFormat, 'pem');
  });

  test('openFile routes a CSR file to the main viewer as CSR data', async () => {
    sinon.stub(vscode.window, 'showOpenDialog').resolves([vscode.Uri.file(csrPath)]);

    await openFile(mockContext())();

    assert.strictEqual(createWebviewPanelStub.firstCall.args[0], 'x509toolkit');
    const panel = createdPanels[0];
    await panel.fireMessage({ type: 'ready' });

    assert.ok(findPostedMessage<ExtToWebviewMsg & { type: 'loading' }>(panel, 'loading'));
    const msg = findPostedMessage<ExtToWebviewMsg & { type: 'csr'; data: { subject: { commonName?: string } } }>(panel, 'csr');
    assert.ok(msg);
    assert.strictEqual(msg?.data.subject.commonName, 'command-route-csr');
  });

  test('openFromExplorer routes a DER certificate file to the main viewer as certificate data', async () => {
    await openFromExplorer(mockContext())(vscode.Uri.file(derCertPath));

    assert.strictEqual(createWebviewPanelStub.firstCall.args[0], 'x509toolkit');
    const panel = createdPanels[0];
    await panel.fireMessage({ type: 'ready' });

    assert.ok(findPostedMessage<ExtToWebviewMsg & { type: 'loading' }>(panel, 'loading'));
    const msg = findPostedMessage<ExtToWebviewMsg & { type: 'certificate'; chain: Array<{ sourceFormat?: string; subject: { commonName?: string } }> }>(panel, 'certificate');
    assert.ok(msg);
    assert.strictEqual(msg?.chain[0].sourceFormat, 'der');
    assert.strictEqual(msg?.chain[0].subject.commonName, 'command-route-cert');
  });

  test('openFromExplorer routes a key file to the key viewer', async () => {
    await openFromExplorer(mockContext())(vscode.Uri.file(keyPath));

    assert.strictEqual(createWebviewPanelStub.firstCall.args[0], 'x509KeyViewer');
    const panel = createdPanels[0];
    await panel.fireMessage({ type: 'keyViewerReady' });

    assert.ok(findPostedMessage<ExtToKeyViewerMsg & { type: 'keyLoading' }>(panel, 'keyLoading'));
    const msg = findPostedMessage<ExtToKeyViewerMsg & { type: 'keyData'; key: { algorithm: string } }>(panel, 'keyData');
    assert.ok(msg);
    assert.strictEqual(msg?.key.algorithm, 'RSA');
  });

  test('openFromExplorer routes unsupported extensions to the main viewer error state', async () => {
    await openFromExplorer(mockContext())(vscode.Uri.file(unsupportedPath));

    assert.strictEqual(createWebviewPanelStub.firstCall.args[0], 'x509toolkit');
    const panel = createdPanels[0];
    await panel.fireMessage({ type: 'ready' });

    assert.ok(findPostedMessage<ExtToWebviewMsg & { type: 'loading' }>(panel, 'loading'));
    const msg = findPostedMessage<ExtToWebviewMsg & { type: 'error'; message: string }>(panel, 'error');
    assert.ok(msg);
    assert.match(msg?.message ?? '', /parse|certificate|data|buffer|unsupported/i);
  });
});