import * as forge from 'node-forge';
import { parseCertificate } from './certificateParser';
import type { CertificateData } from './types';

/**
 * Parse a PKCS#12 / PFX binary and extract all X.509 certificates.
 * Private key material is intentionally ignored — only certificate
 * data is returned to the viewer.
 *
 * @param buf     Raw P12/PFX file contents
 * @param password  Password string (may be empty)
 */
export async function parseP12(buf: Buffer, password: string): Promise<CertificateData[]> {
  // node-forge works with binary strings
  const binaryStr = buf.toString('binary');
  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    const asn1 = forge.asn1.fromDer(binaryStr);
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);
  } catch (err) {
    // A wrong password typically surfaces as a decryption or MAC verification error
    const msg = (err as Error).message ?? String(err);
    if (/mac|integrity|digest|password|decrypt/i.test(msg)) {
      throw new Error('Incorrect password or corrupted file.');
    }
    throw new Error(`Failed to parse P12: ${msg}`);
  }

  // Collect all certificate bags from all SafeContents
  const bags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certBags = bags[forge.pki.oids.certBag] ?? [];

  if (certBags.length === 0) {
    throw new Error('No certificates found in this P12 file.');
  }

  const results: CertificateData[] = [];
  for (const bag of certBags) {
    if (!bag.cert) continue;
    // Convert forge certificate → DER buffer → our CertificateData
    const derStr = forge.asn1.toDer(forge.pki.certificateToAsn1(bag.cert)).getBytes();
    const derBuf = Buffer.from(derStr, 'binary');
    results.push(await parseCertificate(derBuf));
  }

  if (results.length === 0) {
    throw new Error('No valid certificates could be extracted from this P12 file.');
  }

  return results;
}

/**
 * Create a certificates-only PKCS#12 buffer from PEM-encoded certificates.
 * No private key is included. The first PEM should be the end-entity certificate;
 * the rest are CA chain certificates.
 *
 * @param pemCerts  Array of PEM strings (EE cert first, then CAs)
 * @param password  Password to protect the archive (may be empty)
 */
export function createP12Buffer(pemCerts: string[], password: string): Buffer {
  const certs = pemCerts.map(pem => forge.pki.certificateFromPem(pem));
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    null,   // no private key
    certs,
    password,
    { algorithm: '3des' }
  );
  const derStr = forge.asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(derStr, 'binary');
}
