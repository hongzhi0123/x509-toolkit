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
  /** SPKI encoded as PEM (BEGIN PUBLIC KEY) */
  spkiPem: string;
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

export interface PrivateKeyInfo {
  algorithm: string;
  keySize?: number;
  namedCurve?: string;
  /** PKCS#8 DER encoded, formatted as colon-separated hex bytes */
  hex: string;
  /** PKCS#8 PEM-encoded private key */
  pem: string;
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
  /** Present when this cert was loaded from a P12/PFX that included the matching private key */
  privateKey?: PrivateKeyInfo;
}

// ─── Certificate generation ─────────────────────────────────────────────────

export type KeyAlgorithm = 'RSA-2048' | 'RSA-4096' | 'EC-P256' | 'EC-P384' | 'EC-P521';

export interface CertCreateParams {
  cn: string;
  o: string;
  ou: string;
  c: string;
  st: string;
  l: string;
  email: string;
  dnsNames: string;
  ipAddresses: string;
  keyAlgorithm: KeyAlgorithm;
  validityDays: number;
  isCA: boolean;
  keyUsageDigitalSignature: boolean;
  keyUsageKeyEncipherment: boolean;
  keyUsageDataEncipherment: boolean;
  keyUsageKeyCertSign: boolean;
  keyUsageCRLSign: boolean;
  ekuServerAuth: boolean;
  ekuClientAuth: boolean;
  ekuCodeSigning: boolean;
  ekuEmailProtection: boolean;
  signingMode: 'self-signed' | 'ca-signed';
  password: string;
}

export type CreateCertToExtMsg =
  | { type: 'ready' }
  | { type: 'pickCaCert' }
  | { type: 'pickCaKey' }
  | { type: 'generate'; params: CertCreateParams }
  | { type: 'cancel' };

export type ExtToCreateCertMsg =
  | { type: 'caCertLoaded'; subject: string }
  | { type: 'caKeyLoaded'; description: string }
  | { type: 'generating' }
  | { type: 'done' }
  | { type: 'error'; message: string };

export type ExtToWebviewMsg =
  | { type: 'loading' }
  | { type: 'certificate'; chain: CertificateData[]; activeIndex: number }
  | { type: 'error'; message: string }
  | { type: 'caIssuerCert'; cert: CertificateData; url: string }
  | { type: 'caIssuerError'; url: string; message: string }
  | { type: 'privateKeyImported'; certIndex: number; key: PrivateKeyInfo }
  | { type: 'privateKeyImportError'; certIndex: number; message: string }
  | { type: 'requestPassphrase'; requestId: string; fileName: string };

export type WebviewToExtMsg =
  | { type: 'ready' }
  | { type: 'copyToClipboard'; value: string }
  | { type: 'selectCert'; index: number }
  | { type: 'downloadCaIssuer'; url: string }
  | { type: 'exportCert'; pem: string; suggestedName: string }
  | { type: 'createP12'; certPems: string[]; suggestedName: string }
  | { type: 'importPrivateKey'; certIndex: number; spkiPem: string }
  | { type: 'passphraseResponse'; requestId: string; passphrase: string | null };
