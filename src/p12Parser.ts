import * as crypto from 'crypto';
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

/** cert.subject / cert.issuer structural type (matches node-forge's inline type). */
type ForgeDN = { attributes: forge.pki.CertificateField[] };

/**
 * Returns a string key representing a Distinguished Name by concatenating all
 * RDN type/value pairs.  Used to match an issuer DN to a subject DN.
 */
function dnKey(field: ForgeDN): string {
  return field.attributes
    .map(a => `${String(a.type)}=${String(a.value)}`)
    .join('/');
}

/**
 * Sort certificates into chain order: leaf first, then each issuing CA in
 * order, root last.  Handles arbitrary input order and detached roots.
 *
 * node-forge's toPkcs12Asn1 links the private key to the FIRST certificate
 * via localKeyId, so placing the EE cert first is critical when a key is
 * present.
 */
function sortCertChain(certs: forge.pki.Certificate[]): forge.pki.Certificate[] {
  if (certs.length <= 1) return certs;

  // Subjects that appear as someone's issuer (i.e. these are CAs of something in the set)
  const isIssuerOf = new Set<string>();
  for (const c of certs) {
    isIssuerOf.add(dnKey(c.issuer as ForgeDN));
  }

  // The leaf is the cert whose own subject is not issued-to by anyone in the set
  // (i.e. no other cert in the set vouches for it as an issuer)
  let leaf = certs.find(c => !isIssuerOf.has(dnKey(c.subject as ForgeDN)));
  if (!leaf) {
    leaf = certs[0]; // fallback: broken or self-signed-only chain
  }

  const sorted: forge.pki.Certificate[] = [leaf];
  const remaining = new Set(certs.filter(c => c !== leaf));
  let current = leaf;

  while (remaining.size > 0) {
    const wantSubject = dnKey(current.issuer as ForgeDN);
    const next = [...remaining].find(c => dnKey(c.subject as ForgeDN) === wantSubject);
    if (!next) break; // chain broken or root not included — append leftovers below
    sorted.push(next);
    remaining.delete(next);
    current = next;
  }

  // Append anything that couldn't be placed (e.g. a detached extra cert)
  for (const c of remaining) {
    sorted.push(c);
  }

  return sorted;
}

/**
 * Create a PKCS#12 buffer from PEM-encoded certificates and an optional private key.
 * Certificates are sorted into correct chain order (EE first, root last) before
 * being written, regardless of the order they are supplied.
 * When no key is supplied the P12 is certificates-only and password is ignored.
 *
 * @param pemCerts     Array of PEM strings in any order
 * @param password     Password to protect the private key (ignored when no key)
 * @param privateKeyBuf  Raw buffer of a PEM or DER-encoded private key (optional)
 */
export function createP12Buffer(pemCerts: string[], password: string, privateKeyBuf?: Buffer): Buffer {
  const unsorted = pemCerts.map(pem => forge.pki.certificateFromPem(pem));
  const certs = sortCertChain(unsorted);
  const key = privateKeyBuf ? loadPrivateKeyFromBuffer(privateKeyBuf) as forge.pki.rsa.PrivateKey : null;

  if (key !== null) {
    // Verify the private key corresponds to the EE certificate's public key.
    // Uses Node.js crypto so it works for RSA, EC (P-256/384/521), Ed25519, etc.
    // Strategy: derive the public key from the private key and compare SPKI DER bytes
    // against the public key embedded in the certificate.
    const certPubPem = forge.pki.publicKeyToPem(certs[0].publicKey as forge.pki.PublicKey);
    const derivedSpki = crypto.createPublicKey(privateKeyBuf!).export({ type: 'spki', format: 'der' }) as Buffer;
    const certSpki = crypto.createPublicKey(certPubPem).export({ type: 'spki', format: 'der' }) as Buffer;
    if (!derivedSpki.equals(certSpki)) {
      throw new Error('The private key does not match the public key in the certificate.');
    }
  }

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
    key,
    certs,
    key ? password : '',
    { algorithm: '3des' }
  );
  const derStr = forge.asn1.toDer(p12Asn1).getBytes();
  return Buffer.from(derStr, 'binary');
}

/**
 * Generate a self-signed RSA-2048 certificate and return it as a PKCS#12 buffer.
 * The cert includes digital-signature / key-encipherment key usages and
 * TLS server+client extended key usages so it is immediately useful for testing.
 *
 * @param commonName   CN for subject and issuer
 * @param validityDays Number of days from now the cert should be valid
 * @param password     Password to protect the P12 (empty string = no password)
 */
export function createSelfSignedP12(
  commonName: string,
  validityDays: number,
  password: string,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // Generate RSA-2048 key pair asynchronously (chunked via setImmediate in Node.js)
    forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keyPair) => {
      if (err) { reject(err); return; }
      try {
        const cert = forge.pki.createCertificate();
        cert.publicKey = keyPair.publicKey;
        // Random 128-bit serial number
        cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));

        const now = new Date();
        cert.validity.notBefore = now;
        cert.validity.notAfter = new Date(now.getTime() + validityDays * 86_400_000);

        const attrs = [{ name: 'commonName', value: commonName }];
        cert.setSubject(attrs);
        cert.setIssuer(attrs); // self-signed

        cert.setExtensions([
          { name: 'basicConstraints', cA: false, critical: true },
          { name: 'keyUsage', critical: true,
            digitalSignature: true, keyEncipherment: true, dataEncipherment: true },
          { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
          { name: 'subjectKeyIdentifier' },
        ]);

        cert.sign(keyPair.privateKey, forge.md.sha256.create());

        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
          keyPair.privateKey,
          [cert],
          password,
          { algorithm: '3des' },
        );
        resolve(Buffer.from(forge.asn1.toDer(p12Asn1).getBytes(), 'binary'));
      } catch (e) {
        reject(e);
      }
    });
  });
}
