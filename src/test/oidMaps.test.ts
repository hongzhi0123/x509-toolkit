import { EXT_NAMES, EKU_NAMES, SIG_ALG_NAMES } from '../types/oidMaps';

describe('EXT_NAMES', () => {
  const cases: [string, string][] = [
    ['2.5.29.14', 'Subject Key Identifier'],
    ['2.5.29.15', 'Key Usage'],
    ['2.5.29.17', 'Subject Alternative Names'],
    ['2.5.29.19', 'Basic Constraints'],
    ['2.5.29.31', 'CRL Distribution Points'],
    ['2.5.29.32', 'Certificate Policies'],
    ['2.5.29.35', 'Authority Key Identifier'],
    ['2.5.29.37', 'Extended Key Usage'],
    ['1.3.6.1.5.5.7.1.1', 'Authority Information Access'],
    ['1.3.6.1.5.5.7.1.3', 'QC Statements'],
    ['1.3.6.1.4.1.11129.2.4.2', 'Certificate Transparency SCTs'],
  ];

  test.each(cases)('OID %s → %s', (oid, expected) => {
    expect(EXT_NAMES[oid]).toBe(expected);
  });

  it('returns undefined for an unknown OID', () => {
    expect(EXT_NAMES['9.9.9.9.9']).toBeUndefined();
  });
});

describe('EKU_NAMES', () => {
  const cases: [string, string][] = [
    ['1.3.6.1.5.5.7.3.1', 'TLS Server Authentication'],
    ['1.3.6.1.5.5.7.3.2', 'TLS Client Authentication'],
    ['1.3.6.1.5.5.7.3.3', 'Code Signing'],
    ['1.3.6.1.5.5.7.3.4', 'Email Protection'],
    ['1.3.6.1.5.5.7.3.8', 'Time Stamping'],
    ['1.3.6.1.5.5.7.3.9', 'OCSP Signing'],
    ['2.5.29.37.0', 'Any Extended Key Usage'],
  ];

  test.each(cases)('OID %s → %s', (oid, expected) => {
    expect(EKU_NAMES[oid]).toBe(expected);
  });

  it('returns undefined for an unknown OID', () => {
    expect(EKU_NAMES['9.9.9.9.9']).toBeUndefined();
  });
});

describe('SIG_ALG_NAMES', () => {
  const cases: [string, string][] = [
    ['1.2.840.113549.1.1.4', 'MD5 with RSA'],
    ['1.2.840.113549.1.1.5', 'SHA-1 with RSA'],
    ['1.2.840.113549.1.1.11', 'SHA-256 with RSA'],
    ['1.2.840.113549.1.1.12', 'SHA-384 with RSA'],
    ['1.2.840.113549.1.1.13', 'SHA-512 with RSA'],
    ['1.2.840.113549.1.1.10', 'RSASSA-PSS'],
    ['1.2.840.10045.4.3.1', 'ECDSA with SHA-224'],
    ['1.2.840.10045.4.3.2', 'ECDSA with SHA-256'],
    ['1.2.840.10045.4.3.3', 'ECDSA with SHA-384'],
    ['1.2.840.10045.4.3.4', 'ECDSA with SHA-512'],
    ['1.3.101.112', 'Ed25519'],
    ['1.3.101.113', 'Ed448'],
  ];

  test.each(cases)('OID %s → %s', (oid, expected) => {
    expect(SIG_ALG_NAMES[oid]).toBe(expected);
  });

  it('returns undefined for an unknown OID', () => {
    expect(SIG_ALG_NAMES['9.9.9.9.9']).toBeUndefined();
  });
});
