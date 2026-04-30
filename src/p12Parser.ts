import * as crypto from 'crypto';
import * as forge from 'node-forge';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { parseCertificate } from './certificateParser';
import type { CertificateData, CertCreateParams } from './types';

// Use @peculiar/webcrypto which delegates to Node.js crypto under the hood
const webcrypto = new PeculiarCrypto();
x509.cryptoProvider.set(webcrypto);

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

// ─── New certificate generator ───────────────────────────────────────────────

interface AlgSpec {
  keyGenAlg: RsaHashedKeyGenParams | EcKeyGenParams;
  sigAlg: Algorithm | EcdsaParams;
}

function getAlgSpec(algo: CertCreateParams['keyAlgorithm']): AlgSpec {
  const pub = new Uint8Array([1, 0, 1]);
  switch (algo) {
    case 'RSA-2048':
      return { keyGenAlg: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: pub, hash: 'SHA-256' }, sigAlg: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'RSA-4096':
      return { keyGenAlg: { name: 'RSASSA-PKCS1-v1_5', modulusLength: 4096, publicExponent: pub, hash: 'SHA-256' }, sigAlg: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'EC-P256':
      return { keyGenAlg: { name: 'ECDSA', namedCurve: 'P-256' }, sigAlg: { name: 'ECDSA', hash: 'SHA-256' } };
    case 'EC-P384':
      return { keyGenAlg: { name: 'ECDSA', namedCurve: 'P-384' }, sigAlg: { name: 'ECDSA', hash: 'SHA-384' } };
    case 'EC-P521':
      return { keyGenAlg: { name: 'ECDSA', namedCurve: 'P-521' }, sigAlg: { name: 'ECDSA', hash: 'SHA-512' } as EcdsaParams };
  }
}

/**
 * Detect the signing algorithm from a PEM/DER private key for CA-signing use.
 * Returns the CryptoKey and the algorithm that should be used to sign with it.
 */
async function importCaPrivateKey(pemOrDer: string | Buffer): Promise<{ key: CryptoKey; alg: Algorithm | EcdsaParams }> {
  const nodeKey = crypto.createPrivateKey(pemOrDer);
  const pkcs8Der = nodeKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;

  let importAlg: RsaHashedImportParams | EcKeyImportParams;
  let sigAlg: Algorithm | EcdsaParams;

  if (nodeKey.asymmetricKeyType === 'rsa') {
    importAlg = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    sigAlg    = importAlg;
  } else if (nodeKey.asymmetricKeyType === 'ec') {
    const rawCurve     = (nodeKey.asymmetricKeyDetails as { namedCurve?: string }).namedCurve ?? '';
    const namedCurve   = rawCurve === 'prime256v1' ? 'P-256' : rawCurve === 'secp384r1' ? 'P-384' : 'P-521';
    const hash         = namedCurve === 'P-521' ? 'SHA-512' : namedCurve === 'P-384' ? 'SHA-384' : 'SHA-256';
    importAlg = { name: 'ECDSA', namedCurve };
    sigAlg    = { name: 'ECDSA', hash } as EcdsaParams;
  } else {
    throw new Error(`Unsupported CA key type: ${nodeKey.asymmetricKeyType ?? 'unknown'}`);
  }

  const key = await webcrypto.subtle.importKey('pkcs8', new Uint8Array(pkcs8Der), importAlg, false, ['sign']);
  return { key, alg: sigAlg };
}

/**
 * Build a PKCS#12 buffer from arbitrary DER cert + PKCS#8 private key.
 * Works for any key type (RSA, EC) by operating at the ASN.1 level,
 * bypassing node-forge's RSA-only high-level PKCS#12 API.
 * Uses pbeWithSHAAnd3-KeyTripleDESCBC for key encryption and HMAC-SHA1 MAC.
 */
function buildP12FromRawDer(certDer: Buffer, pkcs8Der: Buffer, password: string): Buffer {
  // Key-ID = SHA-1 of the raw cert DER (matches what forge uses for localKeyId)
  const keyId = crypto.createHash('sha1').update(certDer).digest().toString('binary');

  const count = 2048;
  const md = forge.md.sha1;

  // ------------- encrypt the PKCS#8 key -----------------------------------
  const salt    = forge.util.createBuffer(forge.random.getBytesSync(8));
  const encKey  = forge.pkcs12.generateKey(password, salt, 1, count, 24, md.create());
  const encIV   = forge.pkcs12.generateKey(password, salt, 2, count, 8,  md.create());
  const cipher  = forge.cipher.createCipher('3DES-CBC', encKey);
  cipher.start({ iv: encIV });
  cipher.update(forge.util.createBuffer(pkcs8Der.toString('binary')));
  cipher.finish();
  const encKeyBytes = cipher.output.getBytes();

  // EncryptedPrivateKeyInfo wrapped in a ShroudedKeyBag SafeBag
  const encKeyInfo = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      // pbeWithSHAAnd3-KeyTripleDESCBC
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
        forge.asn1.oidToDer('1.2.840.113549.1.12.1.3').getBytes()),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, salt.bytes()),
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
          forge.asn1.integerToDer(count).getBytes()),
      ]),
    ]),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, encKeyBytes),
  ]);

  function localKeyIdAttr(): forge.asn1.Asn1 {
    return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
        forge.asn1.oidToDer(forge.pki.oids.localKeyId).getBytes()),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, keyId),
      ]),
    ]);
  }

  // pkcs8ShroudedKeyBag (1.2.840.113549.1.12.10.1.2)
  const shroudedKeyBag = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
      forge.asn1.oidToDer('1.2.840.113549.1.12.10.1.2').getBytes()),
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [encKeyInfo]),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [localKeyIdAttr()]),
  ]);

  // certBag (1.2.840.113549.1.12.10.1.3) with x509Certificate (1.2.840.113549.1.9.22.1)
  const certBagAsn1 = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
      forge.asn1.oidToDer('1.2.840.113549.1.12.10.1.3').getBytes()),
    forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
          forge.asn1.oidToDer('1.2.840.113549.1.9.22.1').getBytes()),
        forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
          forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false,
            certDer.toString('binary')),
        ]),
      ]),
    ]),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SET, true, [localKeyIdAttr()]),
  ]);

  function toDataContentInfo(safeContents: forge.asn1.Asn1): forge.asn1.Asn1 {
    const der = forge.asn1.toDer(safeContents).getBytes();
    return forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
        forge.asn1.oidToDer(forge.pki.oids.data).getBytes()),
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, der),
      ]),
    ]);
  }

  const authSafe = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    toDataContentInfo(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [shroudedKeyBag])),
    toDataContentInfo(forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [certBagAsn1])),
  ]);
  const authSafeDer = forge.asn1.toDer(authSafe).getBytes();

  // ------------- MAC -------------------------------------------------------
  const macSalt = forge.util.createBuffer(forge.random.getBytesSync(8));
  const macKey  = forge.pkcs12.generateKey(password, macSalt, 3, count, 20, md.create());
  const hmac    = forge.hmac.create();
  hmac.start('sha1', macKey.getBytes());
  hmac.update(authSafeDer);
  const macValue = hmac.getMac().getBytes();

  const macData = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
          forge.asn1.oidToDer('1.3.14.3.2.26').getBytes()), // SHA-1
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.NULL, false, ''),
      ]),
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, macValue),
    ]),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, macSalt.bytes()),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
      forge.asn1.integerToDer(count).getBytes()),
  ]);

  // ------------- PFX -------------------------------------------------------
  const pfx = forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.INTEGER, false,
      forge.asn1.integerToDer(3).getBytes()),
    forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.SEQUENCE, true, [
      forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, false,
        forge.asn1.oidToDer(forge.pki.oids.data).getBytes()),
      forge.asn1.create(forge.asn1.Class.CONTEXT_SPECIFIC, 0, true, [
        forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, false, authSafeDer),
      ]),
    ]),
    macData,
  ]);

  return Buffer.from(forge.asn1.toDer(pfx).getBytes(), 'binary');
}

/**
 * Generate a new X.509 certificate (RSA or EC) and return it as a PKCS#12 buffer.
 * Supports self-signed and CA-signed modes.
 */
export async function generateCertificate(
  params: CertCreateParams,
  caCertPem?: string,
  caPrivKeyPem?: string,
): Promise<Buffer> {
  const { keyGenAlg, sigAlg } = getAlgSpec(params.keyAlgorithm);

  // Generate the new key pair
  const keyPair = await webcrypto.subtle.generateKey(keyGenAlg, true, ['sign', 'verify']) as CryptoKeyPair;

  // Build subject DN
  const dnParts: string[] = [];
  if (params.cn)    dnParts.push(`CN=${params.cn}`);
  if (params.o)     dnParts.push(`O=${params.o}`);
  if (params.ou)    dnParts.push(`OU=${params.ou}`);
  if (params.c)     dnParts.push(`C=${params.c}`);
  if (params.st)    dnParts.push(`ST=${params.st}`);
  if (params.l)     dnParts.push(`L=${params.l}`);
  if (params.email) dnParts.push(`E=${params.email}`);
  const subjectStr = dnParts.join(', ');

  // Determine issuer and signing configuration
  let issuerStr: string;
  let signingKey: CryptoKey;
  let signingAlg: Algorithm | EcdsaParams;
  let issuerPublicKey: x509.PublicKey | undefined;

  if (params.signingMode === 'ca-signed' && caCertPem && caPrivKeyPem) {
    const caCert = new x509.X509Certificate(caCertPem);
    issuerStr = caCert.subject;
    const { key, alg } = await importCaPrivateKey(caPrivKeyPem);
    signingKey = key;
    signingAlg = alg;
    issuerPublicKey = caCert.publicKey;
  } else {
    issuerStr = subjectStr;
    signingKey = keyPair.privateKey;
    signingAlg = sigAlg;
  }

  // Build Subject Alternative Names
  const altNames: x509.GeneralName[] = [];
  if (params.dnsNames) {
    params.dnsNames.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
      .forEach(name => altNames.push(new x509.GeneralName('dns', name)));
  }
  if (params.ipAddresses) {
    params.ipAddresses.split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
      .forEach(ip => altNames.push(new x509.GeneralName('ip', ip)));
  }

  // Build key usage flags
  let kuFlags = 0;
  if (params.keyUsageDigitalSignature) kuFlags |= x509.KeyUsageFlags.digitalSignature;
  if (params.keyUsageKeyEncipherment)  kuFlags |= x509.KeyUsageFlags.keyEncipherment;
  if (params.keyUsageDataEncipherment) kuFlags |= x509.KeyUsageFlags.dataEncipherment;
  if (params.keyUsageKeyCertSign)      kuFlags |= x509.KeyUsageFlags.keyCertSign;
  if (params.keyUsageCRLSign)          kuFlags |= x509.KeyUsageFlags.cRLSign;

  const ekuOids: string[] = [];
  if (params.ekuServerAuth)      ekuOids.push('1.3.6.1.5.5.7.3.1');
  if (params.ekuClientAuth)      ekuOids.push('1.3.6.1.5.5.7.3.2');
  if (params.ekuCodeSigning)     ekuOids.push('1.3.6.1.5.5.7.3.3');
  if (params.ekuEmailProtection) ekuOids.push('1.3.6.1.5.5.7.3.4');

  // Random positive serial (128-bit)
  const serialBytes = crypto.randomBytes(16);
  serialBytes[0] &= 0x7f;
  const serialNumber = serialBytes.toString('hex');

  const now = new Date();
  const notAfter = new Date(now.getTime() + params.validityDays * 86_400_000);

  // Assemble extensions
  const extensions: x509.Extension[] = [
    new x509.BasicConstraintsExtension(params.isCA, params.isCA ? 0 : undefined, true),
  ];
  if (kuFlags) {
    extensions.push(new x509.KeyUsagesExtension(kuFlags as x509.KeyUsageFlags, true));
  }
  if (ekuOids.length > 0) {
    extensions.push(new x509.ExtendedKeyUsageExtension(ekuOids));
  }
  if (altNames.length > 0) {
    extensions.push(new x509.SubjectAlternativeNameExtension(altNames));
  }
  extensions.push(
    await x509.SubjectKeyIdentifierExtension.create(keyPair.publicKey, false, webcrypto),
  );
  if (issuerPublicKey) {
    extensions.push(
      await x509.AuthorityKeyIdentifierExtension.create(issuerPublicKey, false, webcrypto),
    );
  }

  // Generate the certificate
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber,
    subject: subjectStr,
    issuer: issuerStr,
    notBefore: now,
    notAfter,
    signingAlgorithm: signingAlg,
    publicKey: keyPair.publicKey,
    signingKey,
    extensions,
  }, webcrypto);

  // Export key + cert to PKCS#12
  const certDer  = Buffer.from(cert.rawData);
  const pkcs8Der = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', keyPair.privateKey) as ArrayBuffer);

  if (params.keyAlgorithm.startsWith('RSA')) {
    // Use forge's well-tested high-level API for RSA keys
    const certPem = cert.toString('pem');
    return createP12Buffer([certPem], params.password, pkcs8Der);
  } else {
    // Use custom ASN.1 path for EC keys (forge's toPkcs12Asn1 is RSA-only)
    return buildP12FromRawDer(certDer, pkcs8Der, params.password);
  }
}
