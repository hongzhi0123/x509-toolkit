import { parseCertificate, parsePEMChain } from '../certificateParser';
import * as x509 from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';

// ---------------------------------------------------------------------------
// Generate test certificates once for the whole suite
// ---------------------------------------------------------------------------

const webcrypto = new PeculiarCrypto();
x509.cryptoProvider.set(webcrypto);

const EC_ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

let selfSignedPem: string;
let expiredPem: string;
let leafPem: string;
let caPem: string;

beforeAll(async () => {
  // Self-signed EC P-256 certificate — valid until 2035
  const selfKeys = await webcrypto.subtle.generateKey(EC_ALG, false, ['sign', 'verify']);
  const selfCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test Self-Signed, O=Test Org, C=US, ST=California, L=San Francisco',
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter:  new Date('2035-01-01T00:00:00Z'),
    keys: selfKeys,
    signingAlgorithm: EC_ALG,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      await x509.SubjectKeyIdentifierExtension.create(selfKeys.publicKey, false, webcrypto),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    ],
  });
  selfSignedPem = selfCert.toString('pem');

  // Expired certificate — notAfter in the past
  const expKeys = await webcrypto.subtle.generateKey(EC_ALG, false, ['sign', 'verify']);
  const expCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '02',
    name: 'CN=Expired Cert',
    notBefore: new Date('2020-01-01T00:00:00Z'),
    notAfter:  new Date('2021-01-01T00:00:00Z'),
    keys: expKeys,
    signingAlgorithm: EC_ALG,
  });
  expiredPem = expCert.toString('pem');

  // CA certificate for chain testing
  const caKeys = await webcrypto.subtle.generateKey(EC_ALG, false, ['sign', 'verify']);
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '10',
    name: 'CN=Test CA, O=Test Org, C=US',
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter:  new Date('2035-01-01T00:00:00Z'),
    keys: caKeys,
    signingAlgorithm: EC_ALG,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey, false, webcrypto),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  caPem = caCert.toString('pem');

  // Leaf certificate signed by the CA
  const leafKeys = await webcrypto.subtle.generateKey(EC_ALG, false, ['sign', 'verify']);
  const leafCert = await x509.X509CertificateGenerator.create({
    serialNumber: '11',
    subject: 'CN=Test Leaf, O=Test Org, C=US',
    issuer: caCert.subject,
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter:  new Date('2035-01-01T00:00:00Z'),
    signingKey: caKeys.privateKey,
    publicKey: leafKeys.publicKey,
    signingAlgorithm: EC_ALG,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']),
    ],
  });
  leafPem = leafCert.toString('pem');
}, 30_000);

// ---------------------------------------------------------------------------
// parseCertificate — basic structure
// ---------------------------------------------------------------------------

describe('parseCertificate — basic structure', () => {
  it('returns a CertificateData object without throwing', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert).toBeDefined();
  });

  it('extracts the correct commonName from the subject', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.subject.commonName).toBe('Test Self-Signed');
  });

  it('extracts organization, country, state, and locality from the subject', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.subject.organization).toBe('Test Org');
    expect(cert.subject.country).toBe('US');
    expect(cert.subject.state).toBe('California');
    expect(cert.subject.locality).toBe('San Francisco');
  });

  it('has matching subject and issuer for a self-signed certificate', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.isSelfSigned).toBe(true);
    expect(cert.issuer.commonName).toBe(cert.subject.commonName);
  });

  it('sets isCA to false for a non-CA certificate', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.isCA).toBe(false);
  });

  it('sets isCA to true for a CA certificate', async () => {
    const cert = await parseCertificate(caPem);
    expect(cert.isCA).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// parseCertificate — validity
// ---------------------------------------------------------------------------

describe('parseCertificate — validity', () => {
  it('marks a far-future certificate as not expired', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.validity.isExpired).toBe(false);
    expect(cert.validity.daysRemaining).toBeGreaterThan(0);
  });

  it('marks a past certificate as expired', async () => {
    const cert = await parseCertificate(expiredPem);
    expect(cert.validity.isExpired).toBe(true);
    expect(cert.validity.daysRemaining).toBeLessThan(0);
  });

  it('stores notBefore and notAfter as ISO-8601 strings', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.validity.notBefore).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(cert.validity.notAfter).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});

// ---------------------------------------------------------------------------
// parseCertificate — public key
// ---------------------------------------------------------------------------

describe('parseCertificate — public key', () => {
  it('reports the algorithm as ECDSA', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.publicKey.algorithm).toMatch(/ECDSA/i);
  });

  it('reports the named curve as P-256', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.publicKey.namedCurve).toBe('P-256');
  });

  it('includes a non-empty SPKI hex string', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.publicKey.spki).toMatch(/^[0-9a-f:]+$/);
    expect(cert.publicKey.spki.length).toBeGreaterThan(0);
  });

  it('includes a PEM-formatted SPKI', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.publicKey.spkiPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(cert.publicKey.spkiPem).toContain('-----END PUBLIC KEY-----');
  });
});

// ---------------------------------------------------------------------------
// parseCertificate — fingerprints
// ---------------------------------------------------------------------------

describe('parseCertificate — fingerprints', () => {
  it('provides a SHA-1 fingerprint of the correct format', async () => {
    const cert = await parseCertificate(selfSignedPem);
    // SHA-1 = 20 bytes = 59 chars with colons (20 * 2 + 19)
    expect(cert.fingerprints.sha1).toMatch(/^([0-9A-F]{2}:){19}[0-9A-F]{2}$/);
  });

  it('provides a SHA-256 fingerprint of the correct format', async () => {
    const cert = await parseCertificate(selfSignedPem);
    // SHA-256 = 32 bytes = 95 chars with colons
    expect(cert.fingerprints.sha256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  });

  it('produces stable, deterministic fingerprints for the same input', async () => {
    const a = await parseCertificate(selfSignedPem);
    const b = await parseCertificate(selfSignedPem);
    expect(a.fingerprints.sha256).toBe(b.fingerprints.sha256);
  });
});

// ---------------------------------------------------------------------------
// parseCertificate — raw output & extensions
// ---------------------------------------------------------------------------

describe('parseCertificate — raw output and extensions', () => {
  it('returns the raw PEM in the result', async () => {
    const cert = await parseCertificate(selfSignedPem);
    expect(cert.raw).toContain('-----BEGIN CERTIFICATE-----');
    expect(cert.raw).toContain('-----END CERTIFICATE-----');
  });

  it('parses Key Usage extension from the leaf certificate', async () => {
    const cert = await parseCertificate(leafPem);
    const kuExt = cert.extensions.find(e => e.oid === '2.5.29.15');
    expect(kuExt).toBeDefined();
    expect(kuExt?.value).toContain('Digital Signature');
  });

  it('parses EKU extension from the leaf certificate', async () => {
    const cert = await parseCertificate(leafPem);
    const ekuExt = cert.extensions.find(e => e.oid === '2.5.29.37');
    expect(ekuExt).toBeDefined();
    expect(ekuExt?.value).toContain('TLS Server Authentication');
    expect(ekuExt?.value).toContain('TLS Client Authentication');
  });
});

// ---------------------------------------------------------------------------
// parseCertificate — error handling
// ---------------------------------------------------------------------------

describe('parseCertificate — error handling', () => {
  it('throws for a malformed PEM header', async () => {
    await expect(parseCertificate('-----BEGIN CERTIFICATE-----')).rejects.toThrow(
      /malformed/i,
    );
  });

  it('throws for completely invalid input', async () => {
    await expect(parseCertificate('not a certificate')).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// parseCertificate — DER (Buffer) input
// ---------------------------------------------------------------------------

describe('parseCertificate — DER Buffer input', () => {
  it('parses a certificate supplied as a Buffer (DER)', async () => {
    // Obtain the DER bytes from the PEM
    const pem = selfSignedPem
      .replace(/-----BEGIN CERTIFICATE-----/, '')
      .replace(/-----END CERTIFICATE-----/, '')
      .replace(/\s+/g, '');
    const der = Buffer.from(pem, 'base64');

    const cert = await parseCertificate(der);
    expect(cert.subject.commonName).toBe('Test Self-Signed');
  });
});

// ---------------------------------------------------------------------------
// parsePEMChain
// ---------------------------------------------------------------------------

describe('parsePEMChain', () => {
  it('parses a single-certificate PEM chain', async () => {
    const chain = await parsePEMChain(selfSignedPem);
    expect(chain).toHaveLength(1);
    expect(chain[0].subject.commonName).toBe('Test Self-Signed');
  });

  it('parses a two-certificate PEM chain in order', async () => {
    const combined = leafPem + '\n' + caPem;
    const chain = await parsePEMChain(combined);
    expect(chain).toHaveLength(2);
    expect(chain[0].subject.commonName).toBe('Test Leaf');
    expect(chain[1].subject.commonName).toBe('Test CA');
  });

  it('throws when no certificate blocks are present', async () => {
    await expect(parsePEMChain('no certs here')).rejects.toThrow(/no certificate/i);
  });
});
