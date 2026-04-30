/** Mirror of src/types.ts — keep in sync when making changes. */

export interface DistinguishedName {
  raw: string;
  commonName?: string;
  organization?: string;
  organizationalUnit?: string;
  country?: string;
  state?: string;
  locality?: string;
  email?: string;
  domainComponent?: string;
  userId?: string;
}

export interface Validity {
  notBefore: string;
  notAfter: string;
  isExpired: boolean;
  daysRemaining: number;
}

export interface PublicKeyInfo {
  algorithm: string;
  keySize?: number;
  namedCurve?: string;
  spki: string;
}

export interface SignatureInfo {
  algorithm: string;
  value: string;
}

export interface CertExtension {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
  raw: string;
  /** CA Issuer URLs from the Authority Information Access extension */
  caIssuerUrls?: string[];
}

export interface Fingerprints {
  sha1: string;
  sha256: string;
}

export interface CertificateData {
  version: number;
  serialNumber: string;
  subject: DistinguishedName;
  issuer: DistinguishedName;
  validity: Validity;
  publicKey: PublicKeyInfo;
  signature: SignatureInfo;
  extensions: CertExtension[];
  fingerprints: Fingerprints;
  raw: string;
  isCA: boolean;
  isSelfSigned: boolean;
}

export type ExtToWebviewMsg =
  | { type: 'loading' }
  | { type: 'certificate'; chain: CertificateData[]; activeIndex: number }
  | { type: 'error'; message: string }
  | { type: 'caIssuerCert'; cert: CertificateData; url: string }
  | { type: 'caIssuerError'; url: string; message: string };

export type WebviewToExtMsg =
  | { type: 'ready' }
  | { type: 'copyToClipboard'; value: string }
  | { type: 'selectCert'; index: number }
  | { type: 'downloadCaIssuer'; url: string }
  | { type: 'exportCert'; pem: string; suggestedName: string };
