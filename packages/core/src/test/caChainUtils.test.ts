import {
  AuthorityKeyIdentifierExtension,
  SubjectKeyIdentifierExtension,
} from '@peculiar/x509';
import {
  formatIssuerChainFailure,
  isValidIssuer,
  validateIssuerChain,
  type IssuerComparableCertificate,
} from '../utils/caChainUtils';

function stubCertificate(options: {
  subject: string;
  issuer: string;
  akiKeyId?: string;
  skiKeyId?: string;
  throwOnExtension?: boolean;
}): IssuerComparableCertificate {
  return {
    subject: options.subject,
    issuer: options.issuer,
    getExtension(extensionType) {
      if (options.throwOnExtension) {
        throw new Error('extension unavailable');
      }
      if (extensionType === AuthorityKeyIdentifierExtension) {
        return options.akiKeyId ? { keyId: options.akiKeyId } : undefined;
      }
      if (extensionType === SubjectKeyIdentifierExtension) {
        return options.skiKeyId ? { keyId: options.skiKeyId } : undefined;
      }
      return undefined;
    },
  };
}

describe('caChainUtils', () => {
  it('isValidIssuer rejects subject and issuer mismatch', () => {
    const subject = stubCertificate({ subject: 'CN=leaf', issuer: 'CN=issuer-a' });
    const issuer = stubCertificate({ subject: 'CN=issuer-b', issuer: 'CN=root' });
    expect(isValidIssuer(subject, issuer)).toBe(false);
  });

  it('isValidIssuer checks AKI/SKI when both are present', () => {
    const subject = stubCertificate({ subject: 'CN=leaf', issuer: 'CN=issuer', akiKeyId: 'aa' });
    const issuer = stubCertificate({ subject: 'CN=issuer', issuer: 'CN=root', skiKeyId: 'bb' });
    expect(isValidIssuer(subject, issuer)).toBe(false);
  });

  it('isValidIssuer falls back to DN match when extension lookup fails', () => {
    const subject = stubCertificate({ subject: 'CN=leaf', issuer: 'CN=issuer', throwOnExtension: true });
    const issuer = stubCertificate({ subject: 'CN=issuer', issuer: 'CN=root', throwOnExtension: true });
    expect(isValidIssuer(subject, issuer)).toBe(true);
  });

  it('validateIssuerChain returns null for a valid chain', () => {
    const top = stubCertificate({ subject: 'CN=leaf', issuer: 'CN=intermediate', akiKeyId: 'i1' });
    const intermediate = stubCertificate({ subject: 'CN=intermediate', issuer: 'CN=root', skiKeyId: 'i1', akiKeyId: 'r1' });
    const root = stubCertificate({ subject: 'CN=root', issuer: 'CN=root', skiKeyId: 'r1' });
    expect(validateIssuerChain(top, [intermediate, root])).toBeNull();
  });

  it('validateIssuerChain returns first failure details and formatter message', () => {
    const top = stubCertificate({ subject: 'CN=leaf', issuer: 'CN=intermediate' });
    const wrong = stubCertificate({ subject: 'CN=other', issuer: 'CN=root' });
    const failure = validateIssuerChain(top, [wrong]);
    expect(failure).toEqual({ index: 0, expected: 'CN=intermediate', got: 'CN=other' });
    expect(
      formatIssuerChainFailure(failure!)
    ).toBe(
      'Not the correct issuer.\nExpected subject: "CN=intermediate"\nSelected certificate subject: "CN=other"'
    );
  });

  it('formatIssuerChainFailure describes later chain breakage', () => {
    expect(
      formatIssuerChainFailure({ index: 1, expected: 'CN=root', got: 'CN=wrong-root' })
    ).toBe(
      'Certificate 2 in the file is not the issuer of certificate 1.\nExpected: "CN=root"\nGot: "CN=wrong-root"'
    );
  });
});
