import * as vscode from 'vscode';
import { parseCertificate, parsePEMChain, parseCsr } from '../parsers/certificateParser';
import { parseP12 } from '../parsers/p12Parser';
import {
  sendCertificates,
  sendCsr,
  sendError,
  requestPassphraseFromWebview,
} from '../panels/panelManager';

/**
 * Parses PEM text as a CSR or certificate chain and sends the result to the panel.
 * Handles errors internally.
 */
export async function sendParsedPemText(
  text: string,
  panel: vscode.WebviewPanel,
): Promise<void> {
  try {
    if (
      text.includes('-----BEGIN CERTIFICATE REQUEST-----') ||
      text.includes('-----BEGIN NEW CERTIFICATE REQUEST-----')
    ) {
      const csrData = await parseCsr(text);
      sendCsr(panel, csrData);
    } else {
      const chain = await parsePEMChain(text);
      sendCertificates(panel, chain, 0);
    }
  } catch (err: unknown) {
    sendError(panel, (err as Error).message ?? String(err));
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
  panel: vscode.WebviewPanel,
): Promise<void> {
  try {
    if (ext === 'p12' || ext === 'pfx') {
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
      sendCertificates(panel, certs, 0);
      return;
    }

    const asText = raw.toString('utf8').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();

    if (
      asText.includes('-----BEGIN CERTIFICATE REQUEST-----') ||
      asText.includes('-----BEGIN NEW CERTIFICATE REQUEST-----') ||
      ext === 'csr' || ext === 'req'
    ) {
      const csrData = await parseCsr(raw);
      sendCsr(panel, csrData);
      return;
    }

    if (asText.includes('-----BEGIN CERTIFICATE-----')) {
      const chain = await parsePEMChain(asText);
      sendCertificates(panel, chain, 0);
    } else {
      const cert = await parseCertificate(raw);
      sendCertificates(panel, [cert], 0);
    }
  } catch (err: unknown) {
    sendError(panel, (err as Error).message ?? String(err));
  }
}
