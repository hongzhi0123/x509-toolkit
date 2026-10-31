import * as assert from 'assert';
import * as vscode from 'vscode';
import sinon from 'sinon';
import { syncCustomEditorAssociations } from '../../customEditors/certCsrCustomEditor';

type ConfigMock = {
  get: sinon.SinonStub;
  update: sinon.SinonStub;
};

function createConfigMock(getImpl: (key: string, defaultValue?: unknown) => unknown): ConfigMock {
  return {
    get: sinon.stub().callsFake(getImpl),
    update: sinon.stub().resolves(undefined),
  };
}

suite('custom editor associations', () => {
  teardown(() => {
    sinon.restore();
  });

  test('sync adds managed associations when custom editor is enabled', async () => {
    const x509Config = createConfigMock((key, defaultValue) => {
      if (key === 'useCustomEditor.enabled') {
        return true;
      }
      return defaultValue;
    });

    const workbenchConfig = createConfigMock((key, defaultValue) => {
      if (key === 'editorAssociations') {
        return {
          '*.txt': 'default',
        };
      }
      return defaultValue;
    });

    sinon.stub(vscode.workspace, 'getConfiguration').callsFake((section?: string) => {
      if (section === 'x509toolkit') {
        return x509Config as unknown as vscode.WorkspaceConfiguration;
      }
      if (section === 'workbench') {
        return workbenchConfig as unknown as vscode.WorkspaceConfiguration;
      }
      throw new Error(`Unexpected section: ${section ?? '<undefined>'}`);
    });

    await syncCustomEditorAssociations();

    assert.strictEqual(workbenchConfig.update.calledOnce, true);
    const [key, updated, target] = workbenchConfig.update.firstCall.args;
    assert.strictEqual(key, 'editorAssociations');
    assert.strictEqual(target, vscode.ConfigurationTarget.Global);

    const associations = updated as Record<string, string>;
    assert.strictEqual(associations['*.txt'], 'default');
    assert.strictEqual(associations['*.pem'], 'x509toolkit.certCsrViewerEditor');
    assert.strictEqual(associations['*.p12'], 'x509toolkit.certCsrViewerEditor');
    assert.strictEqual(associations['*.pfx'], 'x509toolkit.certCsrViewerEditor');
    assert.strictEqual(associations['*.key'], 'x509toolkit.keyViewerEditor');
    assert.strictEqual(associations['*.crl'], 'x509toolkit.crlViewerEditor');
  });

  test('sync removes managed associations when custom editor is disabled', async () => {
    const x509Config = createConfigMock((key, defaultValue) => {
      if (key === 'useCustomEditor.enabled') {
        return false;
      }
      return defaultValue;
    });

    const workbenchConfig = createConfigMock((key, defaultValue) => {
      if (key === 'editorAssociations') {
        return {
          '*.pem': 'x509toolkit.certViewerEditor',
          '*.p12': 'x509toolkit.certCsrViewerEditor',
          '*.key': 'x509toolkit.keyViewerEditor',
          '*.crl': 'x509toolkit.crlViewerEditor',
          '*.foo': 'x509toolkit.certViewerEditor',
          '*.txt': 'default',
          '*.md': 'default',
        };
      }
      return defaultValue;
    });

    sinon.stub(vscode.workspace, 'getConfiguration').callsFake((section?: string) => {
      if (section === 'x509toolkit') {
        return x509Config as unknown as vscode.WorkspaceConfiguration;
      }
      if (section === 'workbench') {
        return workbenchConfig as unknown as vscode.WorkspaceConfiguration;
      }
      throw new Error(`Unexpected section: ${section ?? '<undefined>'}`);
    });

    await syncCustomEditorAssociations();

    assert.strictEqual(workbenchConfig.update.calledOnce, true);
    const [, updated] = workbenchConfig.update.firstCall.args;
    const associations = updated as Record<string, string>;

    assert.strictEqual(associations['*.txt'], 'default');
    assert.strictEqual(associations['*.md'], 'default');

    assert.strictEqual(associations['*.pem'], undefined);
    assert.strictEqual(associations['*.p12'], undefined);
    assert.strictEqual(associations['*.key'], undefined);
    assert.strictEqual(associations['*.crl'], undefined);
    assert.strictEqual(associations['*.foo'], 'x509toolkit.certViewerEditor');
  });

  test('sync does not update when associations already match desired state', async () => {
    const x509Config = createConfigMock((key, defaultValue) => {
      if (key === 'useCustomEditor.enabled') {
        return true;
      }
      return defaultValue;
    });

    const workbenchConfig = createConfigMock((key, defaultValue) => {
      if (key === 'editorAssociations') {
        return {
          '*.pem': 'x509toolkit.certCsrViewerEditor',
          '*.crt': 'x509toolkit.certCsrViewerEditor',
          '*.cer': 'x509toolkit.certCsrViewerEditor',
          '*.der': 'x509toolkit.certCsrViewerEditor',
          '*.p12': 'x509toolkit.certCsrViewerEditor',
          '*.pfx': 'x509toolkit.certCsrViewerEditor',
          '*.csr': 'x509toolkit.certCsrViewerEditor',
          '*.req': 'x509toolkit.certCsrViewerEditor',
          '*.key': 'x509toolkit.keyViewerEditor',
          '*.pk8': 'x509toolkit.keyViewerEditor',
          '*.p8': 'x509toolkit.keyViewerEditor',
          '*.pub': 'x509toolkit.keyViewerEditor',
          '*.crl': 'x509toolkit.crlViewerEditor',
        };
      }
      return defaultValue;
    });

    sinon.stub(vscode.workspace, 'getConfiguration').callsFake((section?: string) => {
      if (section === 'x509toolkit') {
        return x509Config as unknown as vscode.WorkspaceConfiguration;
      }
      if (section === 'workbench') {
        return workbenchConfig as unknown as vscode.WorkspaceConfiguration;
      }
      throw new Error(`Unexpected section: ${section ?? '<undefined>'}`);
    });

    await syncCustomEditorAssociations();

    assert.strictEqual(workbenchConfig.update.called, false);
  });
});
