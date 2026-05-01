/**
 * Shared type definitions between the extension host and the webview.
 * Keep this file free of any Node.js or VS Code imports so the types
 * can be duplicated as-is inside webview-ui/src/types.ts.
 */

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
  notBefore: string; // ISO-8601
  notAfter: string;  // ISO-8601
  isExpired: boolean;
  daysRemaining: number;
}

export interface PublicKeyInfo {
  algorithm: string;
  keySize?: number;
  namedCurve?: string;
  /** SPKI encoded, formatted as colon-separated hex bytes */
  spki: string;
}

export interface SignatureInfo {
  algorithm: string;
  value: string; // colon-separated hex
}

export interface CertExtension {
  oid: string;
  name: string;
  critical: boolean;
  /** Human-readable value */
  value: string;
  /** Raw extension value as colon-separated hex */
  raw: string;  /** CA Issuer URLs from the Authority Information Access extension */
  caIssuerUrls?: string[];}

export interface Fingerprints {
  sha1: string;   // colon-separated upper-case hex
  sha256: string;
}

export interface PrivateKeyInfo {
  algorithm: string;
  keySize?: number;
  namedCurve?: string;
  /** PKCS#8 PEM-encoded private key */
  pem: string;
}

export interface CertificateData {
  version: number;
  serialNumber: string; // colon-separated hex
  subject: DistinguishedName;
  issuer: DistinguishedName;
  validity: Validity;
  publicKey: PublicKeyInfo;
  signature: SignatureInfo;
  extensions: CertExtension[];
  fingerprints: Fingerprints;
  /** PEM-encoded certificate */
  raw: string;
  isCA: boolean;
  isSelfSigned: boolean;
  /** Present when this cert was loaded from a P12/PFX that included the matching private key */
  privateKey?: PrivateKeyInfo;
}

// ─── Certificate generation ─────────────────────────────────────────────────

export type KeyAlgorithm = 'RSA-2048' | 'RSA-4096' | 'EC-P256' | 'EC-P384' | 'EC-P521';

export interface CertCreateParams {
  // Subject DN
  cn: string;
  o: string;
  ou: string;
  c: string;
  st: string;
  l: string;
  email: string;
  // SANs — newline or comma separated
  dnsNames: string;
  ipAddresses: string;
  // Key
  keyAlgorithm: KeyAlgorithm;
  validityDays: number;
  // Extensions
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
  // Signing
  signingMode: 'self-signed' | 'ca-signed';
  // P12 password
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

// ─── Message protocol ────────────────────────────────────────────────────────

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
  | { type: 'exportCert'; pem: string; suggestedName: string }
  | { type: 'createP12'; certPems: string[]; suggestedName: string };
