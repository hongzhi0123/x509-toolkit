import { parseCrl, parsePemCrlChain } from '../parsers/crlParser';
import {
  X509CertificateGenerator,
  X509CrlGenerator,
  X509CrlReason,
  BasicConstraintsExtension,
  SubjectKeyIdentifierExtension,
  cryptoProvider,
} from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';

// ──────────────────────────────────────────────────────────────────────────────
// Setup crypto provider and generate test fixtures once
// ──────────────────────────────────────────────────────────────────────────────

const webcrypto = new PeculiarCrypto();
cryptoProvider.set(webcrypto);

const EC_ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;

// PEM blocks in the format @peculiar/x509 generates ("BEGIN CRL")
let crlPem: string;
let emptyCrlPem: string;
let expiredCrlPem: string;
let crlDerBuf: Buffer;
// PEM blocks converted to "X509 CRL" headers — required by parsePemCrlChain
let crlX509Pem: string;
let twoCrlX509Pem: string;    // Two "X509 CRL" blocks concatenated

beforeAll(async () => {
  // @peculiar/x509 emits "BEGIN CRL" / "END CRL" headers.
  // parsePemCrlChain specifically matches "BEGIN X509 CRL" headers,
  // while parseCrl (and normaliseToDer) accept any "BEGIN …" header.
  // Use a helper to produce both variants from the generated CRLs.
  function toX509CrlPem(pem: string): string {
    return pem
      .replace(/-----BEGIN CRL-----/g, '-----BEGIN X509 CRL-----')
      .replace(/-----END CRL-----/g, '-----END X509 CRL-----');
  }

  const caKeys = await webcrypto.subtle.generateKey(EC_ALG, true, ['sign', 'verify']);
  const caCert = await X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test CRL CA, O=Test Org, C=US',
    notBefore: new Date('2024-01-01T00:00:00Z'),
    notAfter:  new Date('2035-01-01T00:00:00Z'),
    keys: caKeys,
    signingAlgorithm: EC_ALG,
    extensions: [
      new BasicConstraintsExtension(true, undefined, true),
      await SubjectKeyIdentifierExtension.create(caKeys.publicKey, false, webcrypto),
    ],
  });

  // CRL with one revoked entry, valid until 2035
  const crlObj = await X509CrlGenerator.create({
    issuer: caCert.issuer,
    thisUpdate: new Date('2024-01-15T00:00:00Z'),
    nextUpdate: new Date('2035-01-15T00:00:00Z'),
    entries: [
      {
        serialNumber: '0102',
        revocationDate: new Date('2024-01-10T00:00:00Z'),
        reason: X509CrlReason.keyCompromise,
      },
    ],
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
    signingKey: caKeys.privateKey,
  }, webcrypto);
  crlPem = crlObj.toString('pem');
  crlDerBuf = Buffer.from(crlObj.rawData);
  crlX509Pem = toX509CrlPem(crlPem);

  // Empty CRL (no revocations)
  const emptyCrlObj = await X509CrlGenerator.create({
    issuer: caCert.issuer,
    thisUpdate: new Date('2024-01-15T00:00:00Z'),
    nextUpdate: new Date('2035-01-15T00:00:00Z'),
    entries: [],
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
    signingKey: caKeys.privateKey,
  }, webcrypto);
  emptyCrlPem = emptyCrlObj.toString('pem');

  // Expired CRL (nextUpdate in the past)
  const expiredCrlObj = await X509CrlGenerator.create({
    issuer: caCert.issuer,
    thisUpdate: new Date('2020-01-01T00:00:00Z'),
    nextUpdate: new Date('2020-02-01T00:00:00Z'),
    entries: [],
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' } as EcdsaParams,
    signingKey: caKeys.privateKey,
  }, webcrypto);
  expiredCrlPem = expiredCrlObj.toString('pem');

  // Two CRLs concatenated in one buffer for parsePemCrlChain
  twoCrlX509Pem = crlX509Pem + '\n' + toX509CrlPem(emptyCrlPem);
}, 30_000);

// ──────────────────────────────────────────────────────────────────────────────
// parseCrl — basic structure
// ──────────────────────────────────────────────────────────────────────────────

describe('parseCrl — basic structure', () => {
  it('returns a CrlData object without throwing', () => {
    expect(() => parseCrl(Buffer.from(crlPem))).not.toThrow();
  });

  it('sets sourceFormat to "pem" for PEM input', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.sourceFormat).toBe('pem');
  });

  it('returns the raw PEM in the result', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    // When input is PEM, raw preserves the original header (@peculiar/x509 uses "CRL")
    expect(crl.raw).toContain('-----BEGIN');
    expect(crl.raw).toContain('-----END');
  });

  it('extracts the issuer common name', () => {
    // Either "BEGIN CRL" or "BEGIN X509 CRL" is acceptable PEM
    const crl = parseCrl(Buffer.from(crlX509Pem));
    expect(crl.issuer.commonName).toBe('Test CRL CA');
  });

  it('extracts the issuer organization', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.issuer.organization).toBe('Test Org');
  });

  it('stores thisUpdate as an ISO-8601 string', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.thisUpdate).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('stores nextUpdate as an ISO-8601 string when present', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.nextUpdate).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('marks a future CRL as not expired', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.isExpired).toBe(false);
  });

  it('marks a past CRL as expired', () => {
    const crl = parseCrl(Buffer.from(expiredCrlPem));
    expect(crl.isExpired).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseCrl — revoked certificates
// ──────────────────────────────────────────────────────────────────────────────

describe('parseCrl — revoked certificates', () => {
  it('includes one revoked entry', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.revokedCertificates).toHaveLength(1);
  });

  it('records the serial number of the revoked certificate', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.revokedCertificates[0].serialNumber).toBeTruthy();
  });

  it('records the revocation date as an ISO-8601 string', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    expect(crl.revokedCertificates[0].revocationDate).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('records the revocation reason when provided', () => {
    const crl = parseCrl(Buffer.from(crlPem));
    // keyCompromise should be present
    expect(crl.revokedCertificates[0].reason).toBeTruthy();
  });

  it('returns an empty revoked list for a CRL with no entries', () => {
    const crl = parseCrl(Buffer.from(emptyCrlPem));
    expect(crl.revokedCertificates).toHaveLength(0);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseCrl — DER input
// ──────────────────────────────────────────────────────────────────────────────

describe('parseCrl — DER binary input', () => {
  it('parses a DER-encoded CRL without throwing', () => {
    expect(() => parseCrl(crlDerBuf)).not.toThrow();
  });

  it('sets sourceFormat to "der" for DER input', () => {
    const crl = parseCrl(crlDerBuf);
    expect(crl.sourceFormat).toBe('der');
  });

  it('extracts the same issuer CN as the PEM counterpart', () => {
    const fromPem = parseCrl(Buffer.from(crlPem));
    const fromDer = parseCrl(crlDerBuf);
    expect(fromDer.issuer.commonName).toBe(fromPem.issuer.commonName);
  });

  it('wraps DER output in a PEM block in raw field', () => {
    const crl = parseCrl(crlDerBuf);
    expect(crl.raw).toContain('-----BEGIN X509 CRL-----');
    expect(crl.raw).toContain('-----END X509 CRL-----');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseCrl — error handling
// ──────────────────────────────────────────────────────────────────────────────

describe('parseCrl — error handling', () => {
  it('throws for completely invalid input', () => {
    expect(() => parseCrl(Buffer.from('not a CRL'))).toThrow();
  });

  it('throws for an empty buffer', () => {
    expect(() => parseCrl(Buffer.alloc(0))).toThrow();
  });

  it('throws for a certificate PEM (not a CRL)', () => {
    const certPem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
    expect(() => parseCrl(Buffer.from(certPem))).toThrow();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parsePemCrlChain
// ──────────────────────────────────────────────────────────────────────────────

describe('parsePemCrlChain', () => {
  it('parses a single PEM CRL block as a one-element array', () => {
    const crls = parsePemCrlChain(Buffer.from(crlX509Pem));
    expect(crls).toHaveLength(1);
    expect(crls[0].issuer.commonName).toBe('Test CRL CA');
  });

  it('parses two concatenated PEM CRL blocks as a two-element array', () => {
    const crls = parsePemCrlChain(Buffer.from(twoCrlX509Pem));
    expect(crls).toHaveLength(2);
  });

  it('each entry in the multi-CRL result is a valid CrlData', () => {
    const crls = parsePemCrlChain(Buffer.from(twoCrlX509Pem));
    for (const crl of crls) {
      expect(crl.issuer).toBeDefined();
      expect(crl.thisUpdate).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    }
  });

  it('falls back to parseCrl for a single DER block (no PEM markers found)', () => {
    // DER input has no "-----BEGIN X509 CRL-----" markers
    const crls = parsePemCrlChain(crlDerBuf);
    expect(crls).toHaveLength(1);
    expect(crls[0].issuer.commonName).toBe('Test CRL CA');
  });
});
