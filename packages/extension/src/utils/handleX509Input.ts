import * as vscode from 'vscode';
import { parseCertificate, parsePEMChain, parseCsr, parseP12, looksLikeKeyFile } from '@x509-toolkit/core';
import {
  getOrCreatePanel,
  sendLoading,
  sendCertificates,
  sendCsr,
  sendError,
  requestPassphraseFromWebview,
} from '../panels/mainViewerPanel';
import { openKeyFromBuffer } from '../panels/keyPanel';
import { openCrlFromBuffer } from '../panels/crlPanel';

function isPemCrlText(text: string): boolean {
  return text.includes('-----BEGIN X509 CRL-----');
}

function isCsrText(text: string): boolean {
  return (
    text.includes('-----BEGIN CERTIFICATE REQUEST-----') ||
    text.includes('-----BEGIN NEW CERTIFICATE REQUEST-----')
  );
}

function getMainViewerPanel(context: vscode.ExtensionContext): vscode.WebviewPanel {
  const panel = getOrCreatePanel(context.extensionUri, context);
  sendLoading(panel);
  return panel;
}

/**
 * Parses PEM text and routes it to the appropriate panel.
 * Handles errors internally.
 */
export async function sendParsedPemText(
  text: string,
  context: vscode.ExtensionContext,
): Promise<void> {
  let panel: vscode.WebviewPanel | undefined;
  try {
    const buf = Buffer.from(text);
    if (looksLikeKeyFile(buf)) {
      await openKeyFromBuffer(context, buf, 'private key');
      return;
    }
    if (isPemCrlText(text)) {
      await openCrlFromBuffer(context, buf, 'selected-text.pem', 'pem');
      return;
    }

    panel = getMainViewerPanel(context);
    if (isCsrText(text)) {
      const csrData = await parseCsr(text);
      sendCsr(panel, csrData);
    } else {
      const chain = await parsePEMChain(text);
      chain.forEach(c => { c.sourceFormat = 'pem'; });
      sendCertificates(panel, chain, 0);
    }
  } catch (err: unknown) {
    if (panel) {
      sendError(panel, (err as Error).message ?? String(err));
    } else {
      vscode.window.showErrorMessage((err as Error).message ?? String(err));
    }
  }
}

/**
 * Handles a raw certificate file buffer — dispatches to P12, CSR, PEM chain, or DER
 * based on the file extension and content headers, then sends the result to the panel.
 * For P12/PFX files, prompts for a passphrase via the webview. Handles errors internally.
 */
export async function sendParsedFile(
  raw: Buffer,
  ext: string,
  fileName: string,
  context: vscode.ExtensionContext,
): Promise<void> {
  let panel: vscode.WebviewPanel | undefined;
  try {
    const lowerExt = ext.toLowerCase();
    const asText = raw.toString('utf8').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();

    if (looksLikeKeyFile(raw) || lowerExt === 'key' || lowerExt === 'pk8' || lowerExt === 'p8') {
      await openKeyFromBuffer(context, raw, fileName);
      return;
    }

    if (lowerExt === 'crl' || isPemCrlText(asText)) {
      await openCrlFromBuffer(context, raw, fileName, lowerExt);
      return;
    }

    panel = getMainViewerPanel(context);
    if (lowerExt === 'p12' || lowerExt === 'pfx') {
      const password = await requestPassphraseFromWebview(panel, fileName, {
        title: 'P12 / PFX Password',
        description: `Enter the password for ${fileName}. Leave empty if the file has no password.`,
        buttonLabel: 'Open',
      });
      if (password === null) {
        sendError(panel, 'Operation cancelled.');
        return;
      }
      const certs = await parseP12(raw, password);
      certs.forEach(c => { c.sourceFormat = 'p12'; });
      sendCertificates(panel, certs, 0);
      return;
    }

    if (isCsrText(asText) || lowerExt === 'csr' || lowerExt === 'req') {
      const csrData = await parseCsr(raw);
      sendCsr(panel, csrData);
      return;
    }

    if (asText.includes('-----BEGIN CERTIFICATE-----')) {
      const chain = await parsePEMChain(asText);
      chain.forEach(c => { c.sourceFormat = 'pem'; });
      sendCertificates(panel, chain, 0);
    } else {
      const cert = await parseCertificate(raw);
      cert.sourceFormat = 'der';
      sendCertificates(panel, [cert], 0);
    }
  } catch (err: unknown) {
    if (panel) {
      sendError(panel, (err as Error).message ?? String(err));
    } else {
      vscode.window.showErrorMessage((err as Error).message ?? String(err));
    }
  }
}
