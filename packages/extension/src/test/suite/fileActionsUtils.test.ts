import * as assert from 'assert';
import {
  exportCertificate,
  exportPrivateKey,
  saveCsrAndPrivateKey,
  saveCsrFromMemory,
  savePrivateKeyFromMemory,
  type ViewerFileActionHost,
  buildCertificateExportBuffer,
  getCertificateExportFilters,
  sanitizeSaveBaseName
} from '../../utils/fileActionsUtils';

function createHost(overrides?: Partial<ViewerFileActionHost> & { savePaths?: Array<string | undefined> }) {
  const writes: Array<{ path: string; data: Buffer | string; encoding?: BufferEncoding }> = [];
  const infos: string[] = [];
  const warnings: string[] = [];
  const inputCalls: Array<{ title: string; fieldIds: string[] }> = [];
  const saveDialogs: Array<{ defaultPath: string; title: string }> = [];
  const savePaths = [...(overrides?.savePaths ?? [])];

  const requestInputDialogImpl = overrides?.requestInputDialog;
  const host: ViewerFileActionHost = {
    showSaveDialog: async (options) => {
      saveDialogs.push({ defaultPath: options.defaultPath, title: options.title });
      return savePaths.shift();
    },
    writeFile: (path, data, encoding) => {
      writes.push({ path, data, encoding });
    },
    showInformationMessage: (message) => {
      infos.push(message);
    },
    showWarningMessage: (message) => {
      warnings.push(message);
    },
    requestInputDialog: async (title, fields, options) => {
      inputCalls.push({ title, fieldIds: fields.map(field => field.id) });
      return requestInputDialogImpl ? requestInputDialogImpl(title, fields, options) : null;
    },
  };

  if (overrides) {
    Object.assign(host, overrides);
    host.requestInputDialog = async (title, fields, options) => {
      inputCalls.push({ title, fieldIds: fields.map(field => field.id) });
      return requestInputDialogImpl ? requestInputDialogImpl(title, fields, options) : null;
    };
  }

  return { host, writes, infos, warnings, inputCalls, saveDialogs };
}

suite('fileActionsUtils', () => {
  test('exportCertificate writes DER bytes and reports completion', async () => {
    const { host, writes, infos, saveDialogs } = createHost({ savePaths: ['c:/tmp/cert.der'] });
    const body = Buffer.from('test-der-data').toString('base64');

    await exportCertificate(host, {
      type: 'exportCert',
      pem: `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`,
      suggestedName: 'cert.der',
      format: 'der',
    });

    assert.strictEqual(saveDialogs[0].defaultPath, 'cert.der');
    assert.strictEqual(writes[0].path, 'c:/tmp/cert.der');
    assert.strictEqual((writes[0].data as Buffer).toString('utf8'), 'test-der-data');
    assert.deepStrictEqual(infos, ['Certificate exported to c:/tmp/cert.der']);
  });

  test('exportPrivateKey writes utf8 text', async () => {
    const { host, writes, infos } = createHost({ savePaths: ['c:/tmp/private.key'] });

    await exportPrivateKey(host, {
      type: 'exportPrivateKey',
      keyPem: '-----BEGIN PRIVATE KEY-----\nabc',
      suggestedName: 'private.key',
    });

    assert.strictEqual(writes[0].encoding, 'utf8');
    assert.strictEqual(writes[0].data, '-----BEGIN PRIVATE KEY-----\nabc');
    assert.deepStrictEqual(infos, ['Private key exported to c:/tmp/private.key']);
  });

  test('savePrivateKeyFromMemory warns when no key is available', async () => {
    const { host, warnings, writes } = createHost();
    await savePrivateKeyFromMemory(host, undefined);
    assert.deepStrictEqual(warnings, ['No private key in memory. The key is only available immediately after CSR generation.']);
    assert.strictEqual(writes.length, 0);
  });

  test('saveCsrFromMemory requests name, sanitizes it, and writes file', async () => {
    const { host, writes, infos, inputCalls, saveDialogs } = createHost({
      savePaths: ['c:/tmp/request.csr'],
      requestInputDialog: async () => ({ name: ' request/name ' }),
    });

    await saveCsrFromMemory(host, 'CSR DATA');

    assert.strictEqual(inputCalls[0].title, 'Save Certificate Signing Request');
    assert.strictEqual(saveDialogs[0].defaultPath, 'request_name.csr');
    assert.strictEqual(writes[0].path, 'c:/tmp/request.csr');
    assert.strictEqual(writes[0].data, 'CSR DATA');
    assert.deepStrictEqual(infos, ['CSR saved to c:/tmp/request.csr']);
  });

  test('saveCsrAndPrivateKey writes both files after prompting once', async () => {
    const { host, writes, infos, saveDialogs } = createHost({
      savePaths: ['c:/tmp/certificate.csr', 'c:/tmp/certificate.key'],
      requestInputDialog: async () => ({ name: 'certificate' }),
    });

    await saveCsrAndPrivateKey(host, 'CSR DATA', 'KEY DATA', 'certificate');

    assert.deepStrictEqual(saveDialogs.map(dialog => dialog.defaultPath), ['certificate.csr', 'certificate.key']);
    assert.deepStrictEqual(writes.map(write => write.path), ['c:/tmp/certificate.csr', 'c:/tmp/certificate.key']);
    assert.deepStrictEqual(infos, ['Saved: c:/tmp/certificate.csr and c:/tmp/certificate.key']);
  });

  test('buildCertificateExportBuffer keeps PEM content as utf8', () => {
    const pem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
    const buffer = buildCertificateExportBuffer(pem, 'pem');
    assert.strictEqual(buffer.toString('utf8'), pem);
  });

  test('buildCertificateExportBuffer converts PEM certificate body to DER bytes', () => {
    const body = Buffer.from('test-der-data').toString('base64');
    const pem = `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
    const buffer = buildCertificateExportBuffer(pem, 'der');
    assert.strictEqual(buffer.toString('utf8'), 'test-der-data');
  });

  test('getCertificateExportFilters returns DER filters', () => {
    assert.deepStrictEqual(getCertificateExportFilters('der'), { 'DER Certificate': ['der', 'cer'] });
  });

  test('sanitizeSaveBaseName normalizes unsupported characters and enforces fallback', () => {
    assert.strictEqual(sanitizeSaveBaseName('  my cert/name  ', 'fallback'), 'my_cert_name');
    assert.strictEqual(sanitizeSaveBaseName('   ', 'fallback'), 'fallback');
  });  
});
