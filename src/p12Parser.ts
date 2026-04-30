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
 * Load a private key from a Buffer that is either PEM text or DER binary.
 * Tries PKCS#8 (unencrypted) first, then falls back to PKCS#1 RSA.
 */
function loadPrivateKeyFromBuffer(buf: Buffer): forge.pki.PrivateKey {
  const text = buf.toString('utf8').trim();
  if (text.startsWith('-----BEGIN')) {
    return forge.pki.privateKeyFromPem(text);
  }
  // DER binary — wrap as PEM and try PKCS#8 then PKCS#1
  const b64 = buf.toString('base64');
  const lines = (header: string, footer: string) =>
    `${header}\n${b64.match(/.{1,64}/g)!.join('\n')}\n${footer}`;
  try {
    return forge.pki.privateKeyFromPem(
      lines('-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----')
    );
  } catch {
    return forge.pki.privateKeyFromPem(
      lines('-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----')
    );
  }
}

/**
 * Create a PKCS#12 buffer from PEM-encoded certificates and an optional private key.
 * When no key is supplied the P12 is certificates-only and password is ignored.
 *
 * @param pemCerts     Array of PEM strings (EE cert first, then CAs)
 * @param password     Password to protect the private key (ignored when no key)
 * @param privateKeyBuf  Raw buffer of a PEM or DER-encoded private key (optional)
 */
export function createP12Buffer(pemCerts: string[], password: string, privateKeyBuf?: Buffer): Buffer {
  const certs = pemCerts.map(pem => forge.pki.certificateFromPem(pem));
  const key = privateKeyBuf ? loadPrivateKeyFromBuffer(privateKeyBuf) as forge.pki.rsa.PrivateKey : null;
  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    key,
    certs,
    key ? password : '',
    { algorithm: '3des' }
  );
  const derStr = forge.asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(derStr, 'binary');
}
