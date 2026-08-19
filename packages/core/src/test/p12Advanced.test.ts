import * as crypto from 'crypto';
import { generateCertificate, generateCsr, createP12Buffer, parseP12 } from '../parsers/p12Parser';
import { parseCsr } from '../parsers/certificateParser';
import type { CertCreateParams, CertExtension } from '../types/types';

// Key generation can be slow — allow up to 120 s for the whole suite.
jest.setTimeout(120_000);

// Extension OIDs used in assertions
const OID_KEY_USAGE = '2.5.29.15';
const OID_EKU       = '2.5.29.37';
const OID_SAN       = '2.5.29.17';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeParams(overrides?: Partial<CertCreateParams>): CertCreateParams {
  return {
    cn: 'test.example',
    o: 'Test Org',
    ou: 'Test Unit',
    c: 'US',
    st: 'California',
    l: 'San Jose',
    email: 'test@example.com',
    dnsNames: '',
    ipAddresses: '',
    keyAlgorithm: 'RSA-2048',
    validityDays: 365,
    isCA: false,
    keyUsageDigitalSignature: true,
    keyUsageKeyEncipherment: true,
    keyUsageDataEncipherment: false,
    keyUsageKeyCertSign: false,
    keyUsageCRLSign: false,
    ekuServerAuth: true,
    ekuClientAuth: true,
    ekuCodeSigning: false,
    ekuEmailProtection: false,
    signingMode: 'self-signed',
    password: 'test-password',
    ...overrides,
  };
}

/** Find an extension by OID. */
function findExt(extensions: CertExtension[], oid: string): CertExtension | undefined {
  return extensions.find(e => e.oid === oid);
}

// ---------------------------------------------------------------------------
// createP12Buffer
// ---------------------------------------------------------------------------

describe('createP12Buffer', () => {
  let rsaKeyBuf: Buffer;
  let rootPem: string;

  beforeAll(async () => {
    // Generate an RSA self-signed cert via generateCertificate so we have
    // a PEM cert to feed into createP12Buffer.
    const rsaP12 = await generateCertificate(makeParams({ cn: 'rsa-buffer-test' }));
    const [rsaCert] = await parseP12(rsaP12, 'test-password');
    rootPem = rsaCert.raw;

    // Generate a random RSA key for the mismatch test.
    rsaKeyBuf = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    }).privateKey;
  });

  // -- Basic functionality ---------------------------------------------------

  it('creates a valid PKCS#12 buffer from a single PEM cert (no key)', () => {
    const buf = createP12Buffer([rootPem], '', undefined);
    expect(Buffer.isBuffer(buf)).toBe(true);
    expect(buf.length).toBeGreaterThan(0);
    expect(buf[0]).toBe(0x30); // DER SEQUENCE
  });

  it('round-trips: P12 created by createP12Buffer can be parsed back', async () => {
    const buf = createP12Buffer([rootPem], '', undefined);
    const certs = await parseP12(buf, '');
    expect(certs).toHaveLength(1);
    expect(certs[0].subject.commonName).toBe('rsa-buffer-test');
  });

  it('round-trips with a private key attached (re-pack via PEM key)', async () => {
    const p12 = await generateCertificate(makeParams({ cn: 'roundtrip-key', password: 'pw' }));
    const [cert] = await parseP12(p12, 'pw');
    expect(cert.privateKey).toBeDefined();

    const keyBuf = Buffer.from(cert.privateKey!.pem, 'utf8');
    const repacked = createP12Buffer([cert.raw], 'pw2', keyBuf);
    const [repackedCert] = await parseP12(repacked, 'pw2');
    expect(repackedCert.subject.commonName).toBe('roundtrip-key');
    expect(repackedCert.privateKey).toBeDefined();
  });

  // -- Chain ordering --------------------------------------------------------

  it('places the EE certificate first when a chain is provided', async () => {
    // Generate a root CA, then use it to sign a leaf.
    const rootP12 = await generateCertificate(makeParams({
      cn: 'chain-root',
      isCA: true,
      keyUsageKeyCertSign: true,
      keyUsageDigitalSignature: false,
      keyUsageKeyEncipherment: false,
      password: 'rootpw',
    }));
    const [rootCert] = await parseP12(rootP12, 'rootpw');
    const rootPemLocal = rootCert.raw;
    const rootKeyPem = rootCert.privateKey!.pem;

    const leafP12 = await generateCertificate(
      makeParams({
        cn: 'chain-leaf',
        isCA: false,
        signingMode: 'ca-signed',
        password: 'leafpw',
      }),
      rootPemLocal,
      rootKeyPem,
    );

    const [leafCert] = await parseP12(leafP12, 'leafpw');
    const leafPemLocal = leafCert.raw;
    const leafKeyBuf = Buffer.from(leafCert.privateKey!.pem, 'utf8');

    // Provide certs in reverse order — createP12Buffer should sort leaf first.
    const combined = createP12Buffer([rootPemLocal, leafPemLocal], 'combined', leafKeyBuf);
    const chain = await parseP12(combined, 'combined');
    expect(chain).toHaveLength(2);
    expect(chain[0].subject.commonName).toBe('chain-leaf');
    expect(chain[1].subject.commonName).toBe('chain-root');
  });

  // -- Error handling --------------------------------------------------------

  it('throws when the private key does not match the certificate', () => {
    expect(() => createP12Buffer([rootPem], 'pw', rsaKeyBuf)).toThrow(
      /does not match/i,
    );
  });

  // -- EC key support --------------------------------------------------------

  it('can round-trip an EC cert through parseP12 after generation', async () => {
    // createP12Buffer uses node-forge internally which is RSA-only for PEM
    // parsing.  EC certs are handled by the lower-level buildP12FromRawDer
    // inside generateCertificate.  This test verifies the full EC flow
    // (generate + parse) works end-to-end.
    const ecP12 = await generateCertificate(makeParams({
      keyAlgorithm: 'EC-P256',
      cn: 'ec-p12-roundtrip',
      password: 'ecpw',
    }));
    const [ecCert] = await parseP12(ecP12, 'ecpw');
    expect(ecCert.subject.commonName).toBe('ec-p12-roundtrip');
    expect(ecCert.privateKey).toBeDefined();
    expect(ecCert.privateKey!.algorithm).toMatch(/EC/i);
  });
});

// ---------------------------------------------------------------------------
// generateCertificate
// ---------------------------------------------------------------------------

describe('generateCertificate', () => {
  // -- RSA variants ----------------------------------------------------------

  describe('self-signed RSA-2048', () => {
    let p12: Buffer;

    beforeAll(async () => {
      p12 = await generateCertificate(makeParams({
        cn: 'rsa2048-test',
        keyAlgorithm: 'RSA-2048',
        password: 'pw',
      }));
    });

    it('returns a non-empty Buffer starting with 0x30', () => {
      expect(Buffer.isBuffer(p12)).toBe(true);
      expect(p12.length).toBeGreaterThan(0);
      expect(p12[0]).toBe(0x30);
    });

    it('round-trips: parsed cert has the correct CN', async () => {
      const [cert] = await parseP12(p12, 'pw');
      expect(cert.subject.commonName).toBe('rsa2048-test');
    });

    it('has a private key attached', async () => {
      const [cert] = await parseP12(p12, 'pw');
      expect(cert.privateKey).toBeDefined();
      expect(cert.privateKey!.algorithm).toMatch(/RSA/i);
      expect(cert.privateKey!.keySize).toBe(2048);
    });

    it('is self-signed, not a CA', async () => {
      const [cert] = await parseP12(p12, 'pw');
      expect(cert.isSelfSigned).toBe(true);
      expect(cert.isCA).toBe(false);
    });

    it('contains the configured key usages and EKUs', async () => {
      const [cert] = await parseP12(p12, 'pw');
      const kuExt = findExt(cert.extensions, OID_KEY_USAGE);
      expect(kuExt).toBeDefined();
      expect(kuExt!.value).toContain('Digital Signature');
      expect(kuExt!.value).toContain('Key Encipherment');

      const ekuExt = findExt(cert.extensions, OID_EKU);
      expect(ekuExt).toBeDefined();
      expect(ekuExt!.value).toContain('Server Authentication');
      expect(ekuExt!.value).toContain('Client Authentication');
    });
  });

  it('generates RSA-4096 certificates', async () => {
    const p12 = await generateCertificate(makeParams({
      keyAlgorithm: 'RSA-4096',
      cn: 'rsa4096-test',
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    expect(cert.subject.commonName).toBe('rsa4096-test');
    expect(cert.privateKey?.keySize).toBe(4096);
  });

  // -- EC variants -----------------------------------------------------------

  it('generates EC-P256 certificates', async () => {
    const p12 = await generateCertificate(makeParams({
      keyAlgorithm: 'EC-P256',
      cn: 'ec256-test',
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    expect(cert.subject.commonName).toBe('ec256-test');
    expect(cert.privateKey).toBeDefined();
    expect(cert.privateKey!.algorithm).toMatch(/EC/i);
    expect(cert.privateKey!.namedCurve).toBe('P-256');
  });

  it('generates EC-P384 certificates', async () => {
    const p12 = await generateCertificate(makeParams({
      keyAlgorithm: 'EC-P384',
      cn: 'ec384-test',
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    expect(cert.subject.commonName).toBe('ec384-test');
    expect(cert.privateKey?.namedCurve).toBe('P-384');
  });

  it('generates EC-P521 certificates', async () => {
    const p12 = await generateCertificate(makeParams({
      keyAlgorithm: 'EC-P521',
      cn: 'ec521-test',
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    expect(cert.subject.commonName).toBe('ec521-test');
    expect(cert.privateKey?.namedCurve).toBe('P-521');
  });

  // -- CA-signed -------------------------------------------------------------

  it('generates a CA-signed certificate', async () => {
    const rootP12 = await generateCertificate(makeParams({
      cn: 'ca-root',
      isCA: true,
      keyUsageKeyCertSign: true,
      keyUsageDigitalSignature: false,
      keyUsageKeyEncipherment: false,
      keyAlgorithm: 'EC-P256',
      password: 'rootpw',
    }));
    const [rootCert] = await parseP12(rootP12, 'rootpw');

    const leafP12 = await generateCertificate(
      makeParams({
        cn: 'ca-leaf',
        isCA: false,
        keyAlgorithm: 'RSA-2048',
        signingMode: 'ca-signed',
        password: 'leafpw',
      }),
      rootCert.raw,
      rootCert.privateKey!.pem,
    );
    const [leafCert] = await parseP12(leafP12, 'leafpw');

    expect(leafCert.subject.commonName).toBe('ca-leaf');
    expect(leafCert.issuer.commonName).toBe('ca-root');
    expect(leafCert.isSelfSigned).toBe(false);
    expect(leafCert.isCA).toBe(false);
    expect(leafCert.privateKey).toBeDefined();
  });

  // -- CA certificate --------------------------------------------------------

  it('generates a CA certificate with keyCertSign and cRLSign', async () => {
    const p12 = await generateCertificate(makeParams({
      cn: 'my-ca',
      isCA: true,
      keyUsageKeyCertSign: true,
      keyUsageCRLSign: true,
      keyUsageDigitalSignature: false,
      keyUsageKeyEncipherment: false,
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    expect(cert.isCA).toBe(true);

    const kuExt = findExt(cert.extensions, OID_KEY_USAGE);
    expect(kuExt).toBeDefined();
    expect(kuExt!.value).toContain('Key Cert Sign');
    expect(kuExt!.value).toContain('CRL Sign');
  });

  // -- Subject DN fields -----------------------------------------------------

  it('populates all subject DN fields', async () => {
    const p12 = await generateCertificate(makeParams({
      cn: 'full-dn',
      o: 'Org Inc.',
      ou: 'Engineering',
      c: 'DE',
      st: 'Bavaria',
      l: 'Munich',
      email: 'dn@example.de',
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    expect(cert.subject.commonName).toBe('full-dn');
    expect(cert.subject.organization).toBe('Org Inc.');
    expect(cert.subject.organizationalUnit).toBe('Engineering');
    expect(cert.subject.country).toBe('DE');
    expect(cert.subject.state).toBe('Bavaria');
    expect(cert.subject.locality).toBe('Munich');
    // Email appears in the subject DN
    expect(cert.subject.email).toBe('dn@example.de');
  });

  // -- SANs ------------------------------------------------------------------

  it('includes DNS names in Subject Alternative Name', async () => {
    const p12 = await generateCertificate(makeParams({
      cn: 'san-test',
      dnsNames: 'www.example.com, api.example.com',
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    const sanExt = findExt(cert.extensions, OID_SAN);
    expect(sanExt).toBeDefined();
    expect(sanExt!.value).toContain('www.example.com');
    expect(sanExt!.value).toContain('api.example.com');
  });

  it('includes IP addresses in Subject Alternative Name', async () => {
    const p12 = await generateCertificate(makeParams({
      cn: 'ip-test',
      ipAddresses: '192.168.1.1, 10.0.0.1',
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    const sanExt = findExt(cert.extensions, OID_SAN);
    expect(sanExt).toBeDefined();
    expect(sanExt!.value).toContain('192.168.1.1');
    expect(sanExt!.value).toContain('10.0.0.1');
  });

  // -- Extended Key Usage ----------------------------------------------------

  it('includes only the configured EKUs', async () => {
    const p12 = await generateCertificate(makeParams({
      cn: 'eku-test',
      ekuServerAuth: false,
      ekuClientAuth: false,
      ekuCodeSigning: true,
      ekuEmailProtection: true,
      password: 'pw',
    }));
    const [cert] = await parseP12(p12, 'pw');
    const ekuExt = findExt(cert.extensions, OID_EKU);
    expect(ekuExt).toBeDefined();
    expect(ekuExt!.value).toContain('Code Signing');
    expect(ekuExt!.value).toContain('Email Protection');
    expect(ekuExt!.value).not.toContain('Server Authentication');
    expect(ekuExt!.value).not.toContain('Client Authentication');
  });

  // -- Serial number randomness ----------------------------------------------

  it('generates different serial numbers on successive calls', async () => {
    const p12a = await generateCertificate(makeParams({ cn: 'serial-a', password: 'pw' }));
    const p12b = await generateCertificate(makeParams({ cn: 'serial-a', password: 'pw' }));
    const [certA] = await parseP12(p12a, 'pw');
    const [certB] = await parseP12(p12b, 'pw');
    expect(certA.serialNumber).not.toBe(certB.serialNumber);
  });
});

// ---------------------------------------------------------------------------
// generateCsr
// ---------------------------------------------------------------------------

describe('generateCsr', () => {
  // -- RSA -------------------------------------------------------------------

  describe('RSA-2048 CSR', () => {
    let result: { csrPem: string; privateKeyPem: string };

    beforeAll(async () => {
      result = await generateCsr(makeParams({
        cn: 'csr-rsa-test',
        keyAlgorithm: 'RSA-2048',
      }));
    });

    it('returns a CSR in valid PEM format', () => {
      expect(result.csrPem).toContain('-----BEGIN CERTIFICATE REQUEST-----');
      expect(result.csrPem).toContain('-----END CERTIFICATE REQUEST-----');
    });

    it('returns a valid unencrypted PKCS#8 private key PEM', () => {
      expect(result.privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
      expect(result.privateKeyPem).toContain('-----END PRIVATE KEY-----');
      const key = crypto.createPrivateKey(result.privateKeyPem);
      expect(key.asymmetricKeyType).toBe('rsa');
    });

    it('can be parsed as a certificate request', async () => {
      const csrData = await parseCsr(result.csrPem);
      expect(csrData.subject.commonName).toBe('csr-rsa-test');
    });
  });

  // -- EC --------------------------------------------------------------------

  it('generates an EC-P256 CSR', async () => {
    const result = await generateCsr(makeParams({
      cn: 'csr-ec-test',
      keyAlgorithm: 'EC-P256',
    }));
    expect(result.csrPem).toContain('-----BEGIN CERTIFICATE REQUEST-----');
    const key = crypto.createPrivateKey(result.privateKeyPem);
    expect(key.asymmetricKeyType).toBe('ec');
    const details = key.asymmetricKeyDetails as { namedCurve?: string };
    expect(details.namedCurve).toBe('prime256v1');
  });

  // -- Subject DN ------------------------------------------------------------

  it('includes all subject DN fields in the CSR', async () => {
    const result = await generateCsr(makeParams({
      cn: 'full-csr',
      o: 'CSR Org',
      ou: 'CSR Dept',
      c: 'FR',
      st: 'Île-de-France',
      l: 'Paris',
      email: 'csr@example.fr',
      keyAlgorithm: 'RSA-2048',
    }));
    const csrData = await parseCsr(result.csrPem);
    expect(csrData.subject.commonName).toBe('full-csr');
    expect(csrData.subject.organization).toBe('CSR Org');
    expect(csrData.subject.organizationalUnit).toBe('CSR Dept');
    expect(csrData.subject.country).toBe('FR');
    expect(csrData.subject.state).toBe('Île-de-France');
    expect(csrData.subject.locality).toBe('Paris');
    expect(csrData.subject.email).toBe('csr@example.fr');
  });

  // -- Extensions ------------------------------------------------------------

  it('includes SANs in the CSR when provided', async () => {
    const result = await generateCsr(makeParams({
      cn: 'csr-san',
      dnsNames: 'san1.example.com, san2.example.com',
      keyAlgorithm: 'EC-P256',
    }));
    const csrData = await parseCsr(result.csrPem);
    const sanExt = findExt(csrData.extensions, OID_SAN);
    expect(sanExt).toBeDefined();
    expect(sanExt!.value).toContain('san1.example.com');
    expect(sanExt!.value).toContain('san2.example.com');
  });

  it('includes key usage and EKU extensions in the CSR when configured', async () => {
    const result = await generateCsr(makeParams({
      cn: 'csr-ext',
      keyAlgorithm: 'RSA-2048',
      keyUsageDigitalSignature: true,
      keyUsageKeyEncipherment: true,
      ekuServerAuth: true,
      ekuClientAuth: true,
    }));
    const csrData = await parseCsr(result.csrPem);

    const kuExt = findExt(csrData.extensions, OID_KEY_USAGE);
    expect(kuExt).toBeDefined();
    expect(kuExt!.value).toContain('Digital Signature');
    expect(kuExt!.value).toContain('Key Encipherment');

    const ekuExt = findExt(csrData.extensions, OID_EKU);
    expect(ekuExt).toBeDefined();
    expect(ekuExt!.value).toContain('Server Authentication');
    expect(ekuExt!.value).toContain('Client Authentication');
  });

  // -- Uniqueness ------------------------------------------------------------

  it('generates different CSRs on successive calls (different keys)', async () => {
    const r1 = await generateCsr(makeParams({ cn: 'unique-csr', keyAlgorithm: 'RSA-2048' }));
    const r2 = await generateCsr(makeParams({ cn: 'unique-csr', keyAlgorithm: 'RSA-2048' }));
    expect(r1.csrPem).not.toBe(r2.csrPem);
    expect(r1.privateKeyPem).not.toBe(r2.privateKeyPem);
  });
});
