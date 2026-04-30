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
}

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
  | { type: 'exportCert'; pem: string; suggestedName: string };
