import * as assert from 'assert';
import * as vscode from 'vscode';
import sinon from 'sinon';
import { convertSelectedCertificateText } from '../../commands/convertSelectedCertificateText';

const CERT_PEM = [
  '-----BEGIN CERTIFICATE-----',
  'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=',
  '-----END CERTIFICATE-----',
].join('\n');

type FakeEditor = vscode.TextEditor & {
  __replaceCalls: Array<{ range: unknown; text: string }>;
};

function createFakeEditor(options?: {
  selectedText?: string;
  isEmptySelection?: boolean;
  languageId?: string;
  editResult?: boolean;
}): FakeEditor {
  const replaceCalls: Array<{ range: unknown; text: string }> = [];
  const selectedText = options?.selectedText ?? CERT_PEM;
  const isEmptySelection = options?.isEmptySelection ?? false;
  const languageId = options?.languageId ?? 'plaintext';
  const editResult = options?.editResult ?? true;

  const fakeEditor = {
    selection: { isEmpty: isEmptySelection },
    document: {
      languageId,
      getText: () => selectedText,
    },
    edit: async (callback: (editBuilder: { replace: (range: unknown, text: string) => void }) => void) => {
      const editBuilder = {
        replace: (range: unknown, text: string) => {
          replaceCalls.push({ range, text });
        },
      };
      callback(editBuilder);
      return editResult;
    },
    __replaceCalls: replaceCalls,
  } as unknown as FakeEditor;

  return fakeEditor;
}

suite('convertSelectedCertificateText command', () => {
  teardown(() => {
    sinon.restore();
  });

  test('shows warning when there is no active editor', async () => {
    sinon.stub(vscode.window, 'activeTextEditor').value(undefined);
    const warnStub = sinon.stub(vscode.window, 'showWarningMessage').resolves(undefined);

    await convertSelectedCertificateText()();

    assert.ok(warnStub.calledOnce);
    assert.strictEqual(warnStub.firstCall.args[0], 'No active editor found.');
  });

  test('shows warning when selected text does not contain PEM markers', async () => {
    const fakeEditor = createFakeEditor({ selectedText: 'not a cert' });
    sinon.stub(vscode.window, 'activeTextEditor').value(fakeEditor);
    const warnStub = sinon.stub(vscode.window, 'showWarningMessage').resolves(undefined);

    await convertSelectedCertificateText()();

    assert.ok(warnStub.calledOnce);
    assert.strictEqual(warnStub.firstCall.args[0], 'Selected text does not contain PEM certificate markers.');
  });

  test('copies converted base64 output to clipboard', async () => {
    const fakeEditor = createFakeEditor({ selectedText: CERT_PEM });
    sinon.stub(vscode.window, 'activeTextEditor').value(fakeEditor);

    const quickPickStub = sinon.stub(vscode.window, 'showQuickPick');
    quickPickStub.onCall(0).resolves({ label: 'Base64 only (no markers)', mode: 'base64' } as never);
    quickPickStub.onCall(1).resolves({ label: 'Copy to clipboard', destination: 'copy' } as never);

    const infoStub = sinon.stub(vscode.window, 'showInformationMessage').resolves(undefined);

    await convertSelectedCertificateText()();

    const clipboardText = await vscode.env.clipboard.readText();
    assert.strictEqual(clipboardText, 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=');
    assert.ok(infoStub.calledOnce);
    assert.strictEqual(infoStub.firstCall.args[0], 'Converted certificate text copied to clipboard.');
  });

  test('replaces selection with single-line PEM output', async () => {
    const fakeEditor = createFakeEditor({ selectedText: CERT_PEM });
    sinon.stub(vscode.window, 'activeTextEditor').value(fakeEditor);

    const quickPickStub = sinon.stub(vscode.window, 'showQuickPick');
    quickPickStub.onCall(0).resolves({ label: 'PEM (single line)', mode: 'pem-single-line' } as never);
    quickPickStub.onCall(1).resolves({ label: 'Replace selection', destination: 'replace-selection' } as never);

    const infoStub = sinon.stub(vscode.window, 'showInformationMessage').resolves(undefined);

    await convertSelectedCertificateText()();

    assert.strictEqual(fakeEditor.__replaceCalls.length, 1);
    assert.strictEqual(
      fakeEditor.__replaceCalls[0].text,
      '-----BEGIN CERTIFICATE-----QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=-----END CERTIFICATE-----',
    );
    assert.ok(infoStub.calledOnce);
    assert.strictEqual(infoStub.firstCall.args[0], 'Selected certificate text converted.');
  });

  test('opens converted output in a new document', async () => {
    const fakeEditor = createFakeEditor({ selectedText: CERT_PEM, languageId: 'plaintext' });
    sinon.stub(vscode.window, 'activeTextEditor').value(fakeEditor);

    const quickPickStub = sinon.stub(vscode.window, 'showQuickPick');
    quickPickStub.onCall(0).resolves({ label: 'PEM (64-char wrapped)', mode: 'pem-wrapped' } as never);
    quickPickStub.onCall(1).resolves({ label: 'Open in new document', destination: 'new-document' } as never);

    const docStub = { uri: vscode.Uri.parse('untitled:converted-cert') } as unknown as vscode.TextDocument;
    const openDocStub = sinon.stub(vscode.workspace, 'openTextDocument').resolves(docStub);
    const showDocStub = sinon.stub(vscode.window, 'showTextDocument').resolves({} as vscode.TextEditor);

    await convertSelectedCertificateText()();

    assert.ok(openDocStub.calledOnce);
    const openArgs = openDocStub.firstCall.args[0] as { content: string; language: string };
    assert.strictEqual(openArgs.language, 'plaintext');
    assert.ok(openArgs.content.includes('-----BEGIN CERTIFICATE-----'));
    assert.ok(showDocStub.calledOnce);
    assert.strictEqual(showDocStub.firstCall.args[0], docStub);
  });
});
