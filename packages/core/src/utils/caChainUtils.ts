import {
  AuthorityKeyIdentifierExtension,
  SubjectKeyIdentifierExtension,
} from '@peculiar/x509';

export type IssuerComparableCertificate = {
  subject: string;
  issuer: string;
  getExtension(
    extensionType: typeof AuthorityKeyIdentifierExtension | typeof SubjectKeyIdentifierExtension
  ): { keyId?: string } | undefined;
};

export type IssuerChainFailure = {
  index: number;
  expected: string;
  got: string;
};

export function isValidIssuer(
  subject: IssuerComparableCertificate,
  issuerCandidate: IssuerComparableCertificate
): boolean {
  if (issuerCandidate.subject !== subject.issuer) {
    return false;
  }

  try {
    const aki = subject.getExtension(AuthorityKeyIdentifierExtension);
    const ski = issuerCandidate.getExtension(SubjectKeyIdentifierExtension);
    if (aki?.keyId && ski?.keyId) {
      return aki.keyId === ski.keyId;
    }
  } catch {
  }

  return true;
}

export function validateIssuerChain(
  topCertificate: IssuerComparableCertificate,
  candidateChain: IssuerComparableCertificate[]
): IssuerChainFailure | null {
  let previous = topCertificate;

  for (let index = 0; index < candidateChain.length; index++) {
    const candidate = candidateChain[index];
    if (!isValidIssuer(previous, candidate)) {
      return {
        index,
        expected: previous.issuer,
        got: candidate.subject,
      };
    }
    previous = candidate;
  }

  return null;
}

export function formatIssuerChainFailure(failure: IssuerChainFailure): string {
  if (failure.index === 0) {
    return `Not the correct issuer.\nExpected subject: "${failure.expected}"\nSelected certificate subject: "${failure.got}"`;
  }

  return `Certificate ${failure.index + 1} in the file is not the issuer of certificate ${failure.index}.\nExpected: "${failure.expected}"\nGot: "${failure.got}"`;
}
