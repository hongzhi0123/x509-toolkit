import * as assert from 'assert';
import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';
import * as tls from 'tls';
import * as vscode from 'vscode';
import sinon from 'sinon';
import * as mainViewerPanel from '../../panels/mainViewerPanel';
import { inspectTlsServer } from '../../commands/inspectTlsServer';

type FakePanel = vscode.WebviewPanel & {
  postedMessages: Array<{ type: string; [key: string]: unknown }>;
};

function mockContext(): vscode.ExtensionContext {
  return {
    subscriptions: [],
    extensionUri: vscode.Uri.file('d:/Dev/ai/x509-viewer/x509-toolkit/packages/extension'),
  } as unknown as vscode.ExtensionContext;
}

function createFakePanel(): FakePanel {
  const postedMessages: Array<{ type: string; [key: string]: unknown }> = [];
  const webview = {
    html: '',
    options: {},
    cspSource: 'vscode-webview-resource:',
    asWebviewUri: (uri: vscode.Uri) => uri,
    postMessage: async (msg: { type: string; [key: string]: unknown }) => {
      postedMessages.push(msg);
      return true;
    },
    onDidReceiveMessage: () => ({ dispose() {} }),
  } as unknown as vscode.Webview;

  return {
    viewType: 'x509toolkit',
    title: 'X.509 Toolkit',
    webview,
    postedMessages,
    options: { enableFindWidget: false, retainContextWhenHidden: true },
    viewColumn: vscode.ViewColumn.Active,
    visible: true,
    active: true,
    reveal() {},
    dispose() {},
    onDidDispose: () => ({ dispose() {} }),
    iconPath: undefined,
    busy: false,
    badge: undefined,
    activeViewColumn: vscode.ViewColumn.Active,
  } as unknown as FakePanel;
}

async function listenTlsServer(options: tls.TlsOptions): Promise<{ server: tls.Server; port: number }> {
  const server = tls.createServer(options);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('Failed to bind TLS test server to a TCP port.');
  }

  return { server, port: address.port };
}

async function listenPlainServer(): Promise<{ server: net.Server; port: number }> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    // Keep the socket open so the TLS client waits until its timeout fires.
    socket.on('error', () => undefined);
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('Failed to bind plain TCP test server to a port.');
  }

  (server as net.Server & { __testSockets?: Set<net.Socket> }).__testSockets = sockets;
  return { server, port: address.port };
}

async function closeServer(server: net.Server | tls.Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

suite('inspectTlsServer command', () => {
  let panel: FakePanel;
  let tlsServer: tls.Server;
  let tlsPort: number;
  let hangingServer: net.Server;
  let hangingPort: number;

  suiteSetup(async () => {
    const certPath = path.resolve(__dirname, '../../../../test-fixtures/ui-e2e-root-ca.crt');
    const keyPath = path.resolve(__dirname, '../../../../test-fixtures/ui-e2e-root-ca.key');
    const cert = fs.readFileSync(certPath, 'utf8');
    const key = fs.readFileSync(keyPath, 'utf8');

    const tlsListener = await listenTlsServer({ cert, key });
    tlsServer = tlsListener.server;
    tlsPort = tlsListener.port;

    const plainListener = await listenPlainServer();
    hangingServer = plainListener.server;
    hangingPort = plainListener.port;
  });

  suiteTeardown(async () => {
    const tracked = (hangingServer as net.Server & { __testSockets?: Set<net.Socket> }).__testSockets;
    for (const socket of tracked ?? []) {
      socket.destroy();
    }
    await closeServer(tlsServer);
    await closeServer(hangingServer);
  });

  setup(() => {
    panel = createFakePanel();
    sinon.stub(vscode.window, 'showInputBox');
    sinon.stub(mainViewerPanel, 'getOrCreatePanel').returns(panel);
    sinon.stub(mainViewerPanel, 'sendLoading');
    sinon.stub(mainViewerPanel, 'sendCertificates');
    sinon.stub(mainViewerPanel, 'sendError');
  });

  teardown(() => {
    sinon.restore();
  });

  test('successfully inspects TLS server and sends parsed chain', async () => {
    const showInputBoxStub = vscode.window.showInputBox as sinon.SinonStub;
    showInputBoxStub.resolves(`127.0.0.1:${tlsPort}`);

    await inspectTlsServer(mockContext())();

    const sendLoadingStub = mainViewerPanel.sendLoading as sinon.SinonStub;
    assert.ok(sendLoadingStub.calledOnce);
    assert.strictEqual(sendLoadingStub.firstCall.args[1], 'Resolving 127.0.0.1…');

    const sendCertStub = mainViewerPanel.sendCertificates as sinon.SinonStub;
    assert.ok(sendCertStub.calledOnce);
    assert.strictEqual(sendCertStub.firstCall.args[2], 0);
    assert.ok(Array.isArray(sendCertStub.firstCall.args[1]));
    assert.ok(sendCertStub.firstCall.args[1].length >= 1);

    const tlsInfo = sendCertStub.firstCall.args[3] as {
      host: string;
      port: number;
      protocol: string;
      cipher: string;
      steps: string[];
    };
    assert.strictEqual(tlsInfo.host, '127.0.0.1');
    assert.strictEqual(tlsInfo.port, tlsPort);
    assert.match(tlsInfo.protocol, /^TLS/);
    assert.notStrictEqual(tlsInfo.cipher, 'unknown');
    assert.ok(tlsInfo.steps.some((step) => step.includes(`Connecting to 127.0.0.1:${tlsPort}`)));
    assert.ok(tlsInfo.steps.some((step) => step.includes('TLS handshake complete')));
    assert.ok((mainViewerPanel.sendError as sinon.SinonStub).notCalled);
  });

  test('handles connection failure and reports error message', async () => {
    const failingPort = await new Promise<number>((resolve, reject) => {
      const tempServer = net.createServer();
      tempServer.once('error', reject);
      tempServer.listen(0, '127.0.0.1', () => {
        const address = tempServer.address();
        if (!address || typeof address === 'string') {
          tempServer.close(() => reject(new Error('Failed to capture temporary port.')));
          return;
        }
        const port = address.port;
        tempServer.close((err) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(port);
        });
      });
    });

    const showInputBoxStub = vscode.window.showInputBox as sinon.SinonStub;
    showInputBoxStub.resolves(`127.0.0.1:${failingPort}`);

    await inspectTlsServer(mockContext())();

    const sendErrorStub = mainViewerPanel.sendError as sinon.SinonStub;
    assert.ok(sendErrorStub.calledOnce);
    const message = sendErrorStub.firstCall.args[1] as string;
    assert.match(message, new RegExp(`^Failed to connect to 127\\.0\\.0\\.1:${failingPort}:`));
    assert.match(message, /ECONNREFUSED|connect/i);
  });

  test('handles TLS timeout and reports timeout error', async function () {
    this.timeout(25_000);

    const showInputBoxStub = vscode.window.showInputBox as sinon.SinonStub;
    showInputBoxStub.resolves(`127.0.0.1:${hangingPort}`);

    await inspectTlsServer(mockContext())();

    const sendErrorStub = mainViewerPanel.sendError as sinon.SinonStub;
    assert.ok(sendErrorStub.calledOnce);
    const message = sendErrorStub.firstCall.args[1] as string;
    assert.match(message, new RegExp(`^Failed to connect to 127\\.0\\.0\\.1:${hangingPort}:`));
    assert.match(message, /timed out/i);
  });

  test('returns early when user cancels host prompt', async () => {
    const showInputBoxStub = vscode.window.showInputBox as sinon.SinonStub;
    showInputBoxStub.resolves(undefined);

    await inspectTlsServer(mockContext())();

    assert.ok((mainViewerPanel.getOrCreatePanel as sinon.SinonStub).notCalled);
    assert.ok((mainViewerPanel.sendLoading as sinon.SinonStub).notCalled);
    assert.ok((mainViewerPanel.sendCertificates as sinon.SinonStub).notCalled);
    assert.ok((mainViewerPanel.sendError as sinon.SinonStub).notCalled);
  });
});
