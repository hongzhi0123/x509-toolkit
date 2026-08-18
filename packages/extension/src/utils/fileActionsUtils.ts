import { type InputDialogFieldDef, type WebviewToExtMsg } from '@x509-toolkit/core';

type DialogOptions = {
  defaultPath: string;
  filters: { [name: string]: string[] };
  saveLabel: string;
  title: string;
};

type InputDialogOptions = {
  icon?: string;
  description?: string;
  confirmLabel?: string;
  cancelLabel?: string;
};

export type CertificateExportFormat = 'pem' | 'der';

export type ViewerFileActionHost = {
  showSaveDialog(options: DialogOptions): Promise<string | undefined>;
  writeFile(path: string, data: Buffer | string, encoding?: BufferEncoding): void;
  showInformationMessage(message: string): void;
  showWarningMessage(message: string): void;
  requestInputDialog(
    title: string,
    fields: InputDialogFieldDef[],
    options?: InputDialogOptions
  ): Promise<Record<string, string> | null>;
};

export async function exportCertificate(
  host: ViewerFileActionHost,
  msg: Extract<WebviewToExtMsg, { type: 'exportCert' }>
): Promise<void> {
  const uri = await host.showSaveDialog({
    defaultPath: msg.suggestedName,
    filters: getCertificateExportFilters(msg.format),
    saveLabel: 'Export Certificate',
    title: `Export Certificate as ${msg.format.toUpperCase()}`,
  });
  if (!uri) {
    return;
  }

  host.writeFile(uri, buildCertificateExportBuffer(msg.pem, msg.format));
  host.showInformationMessage(`Certificate exported to ${uri}`);
}

export async function exportPrivateKey(
  host: ViewerFileActionHost,
  msg: Extract<WebviewToExtMsg, { type: 'exportPrivateKey' }>
): Promise<void> {
  const uri = await host.showSaveDialog({
    defaultPath: msg.suggestedName,
    filters: { 'Private Key': ['key', 'pem'], 'All Files': ['*'] },
    saveLabel: 'Export Private Key',
    title: 'Export Private Key',
  });
  if (!uri) {
    return;
  }

  host.writeFile(uri, msg.keyPem, 'utf8');
  host.showInformationMessage(`Private key exported to ${uri}`);
}

export async function savePrivateKeyFromMemory(
  host: ViewerFileActionHost,
  privateKeyPem: string | undefined
): Promise<boolean> {
  if (!privateKeyPem) {
    host.showWarningMessage('No private key in memory. The key is only available immediately after CSR generation.');
    return false;
  }

  const keyNameResult = await host.requestInputDialog(
    'Save Private Key',
    [{ id: 'name', label: 'File name', type: 'text', value: 'private', placeholder: 'private', required: true, hint: 'A .key extension will be added automatically.' }],
    { icon: '🗝️', confirmLabel: 'Save…' }
  );
  if (!keyNameResult) {
    return false;
  }

  const safeKeyName = sanitizeSaveBaseName(keyNameResult.name, 'private');
  const keyPath = await host.showSaveDialog({
    defaultPath: `${safeKeyName}.key`,
    filters: { 'Private Key': ['key', 'pem'], 'All Files': ['*'] },
    saveLabel: 'Save Private Key',
    title: 'Save Private Key',
  });
  if (!keyPath) {
    return false;
  }

  host.writeFile(keyPath, privateKeyPem, 'utf8');
  host.showInformationMessage(`Private key saved to ${keyPath}`);
  return true;
}

export async function saveCsrFromMemory(
  host: ViewerFileActionHost,
  csrPem: string | undefined
): Promise<boolean> {
  if (!csrPem) {
    host.showWarningMessage('No CSR in memory.');
    return false;
  }

  const csrNameResult = await host.requestInputDialog(
    'Save Certificate Signing Request',
    [{ id: 'name', label: 'File name', type: 'text', value: 'request', placeholder: 'request', required: true, hint: 'A .csr extension will be added automatically.' }],
    { icon: '📄', confirmLabel: 'Save…' }
  );
  if (!csrNameResult) {
    return false;
  }

  const safeCsrName = sanitizeSaveBaseName(csrNameResult.name, 'request');
  const csrPath = await host.showSaveDialog({
    defaultPath: `${safeCsrName}.csr`,
    filters: { 'Certificate Signing Request': ['csr', 'req', 'pem'], 'All Files': ['*'] },
    saveLabel: 'Save CSR',
    title: 'Save Certificate Signing Request',
  });
  if (!csrPath) {
    return false;
  }

  host.writeFile(csrPath, csrPem, 'utf8');
  host.showInformationMessage(`CSR saved to ${csrPath}`);
  return true;
}

export async function saveCsrAndPrivateKey(
  host: ViewerFileActionHost,
  csrPem: string | undefined,
  privateKeyPem: string | undefined,
  suggestedName: string
): Promise<boolean> {
  if (!csrPem || !privateKeyPem) {
    host.showWarningMessage('CSR or private key is no longer in memory.');
    return false;
  }

  const bothNameResult = await host.requestInputDialog(
    'Save CSR and Private Key',
    [{ id: 'name', label: 'Base file name', type: 'text', value: suggestedName, placeholder: 'certificate', required: true, hint: 'Extensions .csr and .key will be added automatically.' }],
    { icon: '💾', description: 'Both files will be saved with the same base name.', confirmLabel: 'Save…' }
  );
  if (!bothNameResult) {
    return false;
  }

  const safeName = sanitizeSaveBaseName(bothNameResult.name, 'certificate');
  const csrPath = await host.showSaveDialog({
    defaultPath: `${safeName}.csr`,
    filters: { 'Certificate Signing Request': ['csr', 'req', 'pem'], 'All Files': ['*'] },
    saveLabel: 'Save CSR',
    title: 'Save Certificate Signing Request',
  });
  if (!csrPath) {
    return false;
  }

  host.writeFile(csrPath, csrPem, 'utf8');
  const keyPath = await host.showSaveDialog({
    defaultPath: `${safeName}.key`,
    filters: { 'Private Key': ['key', 'pem'], 'All Files': ['*'] },
    saveLabel: 'Save Private Key',
    title: 'Save Private Key',
  });
  if (!keyPath) {
    return false;
  }

  host.writeFile(keyPath, privateKeyPem, 'utf8');
  host.showInformationMessage(`Saved: ${csrPath} and ${keyPath}`);
  return true;
}

export function getCertificateExportFilters(format: CertificateExportFormat): { [name: string]: string[] } {
  return format === 'der'
    ? { 'DER Certificate': ['der', 'cer'] }
    : { 'PEM Certificate': ['pem', 'crt', 'cer'] };
}

export function buildCertificateExportBuffer(pem: string, format: CertificateExportFormat): Buffer {
  if (format === 'der') {
    const b64 = pem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    return Buffer.from(b64, 'base64');
  }

  return Buffer.from(pem, 'utf8');
}

export function sanitizeSaveBaseName(name: string, fallback: string): string {
  return name.trim().replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 128) || fallback;
}
