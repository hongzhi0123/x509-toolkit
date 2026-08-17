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
  jurisdictionCountry?: string;
  jurisdictionState?: string;
  jurisdictionLocality?: string;
  postalCode?: string;
  streetAddress?: string;
  organizationIdentifier?: string;
  serialNumber?: string;
  businessCategory?: string;
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
  /** SPKI encoded as PEM (BEGIN PUBLIC KEY) */
  spkiPem: string;
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
  /** PKCS#8 DER encoded, formatted as colon-separated hex bytes */
  hex: string;
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
  /** Format of the source file this certificate was loaded from */
  sourceFormat?: 'pem' | 'der' | 'p12';
}

export interface TlsConnectionInfo {
  host: string;
  port: number;
  /** Resolved IP address of the server */
  ip: string;
  /** TLS protocol version, e.g. 'TLSv1.3' */
  protocol: string;
  /** Negotiated cipher suite name */
  cipher: string;
  /** Ordered log of handshake progress steps */
  steps: string[];
}

export interface CsrData {
  subject: DistinguishedName;
  publicKey: PublicKeyInfo;
  signatureAlgorithm: string;
  extensions: CertExtension[];
  /** PEM-encoded PKCS#10 Certificate Signing Request */
  raw: string;
  /** Describes the associated private key (algorithm + encryption status); present only when the
   *  key is held in extension-host memory — key material is never sent to the webview */
  privateKeyDescription?: string;
}

// ─── Certificate Revocation List ─────────────────────────────────────────────

export interface CrlRevokedEntry {
  /** Colon-separated uppercase hex serial number */
  serialNumber: string;
  /** ISO-8601 revocation date */
  revocationDate: string;
  /** Human-readable reason string (e.g. "keyCompromise"), omitted if unspecified */
  reason?: string;
  /** ISO-8601 invalidity date from the Invalidity Date extension, if present */
  invalidityDate?: string;
}

export interface CrlData {
  /** CRL version: 1 (v1) or 2 (v2) */
  version: number;
  issuer: DistinguishedName;
  signatureAlgorithm: string;
  /** ISO-8601 */
  thisUpdate: string;
  /** ISO-8601 — absent on CRLs that never expire */
  nextUpdate?: string;
  /** Whether nextUpdate is in the past */
  isExpired: boolean;
  revokedCertificates: CrlRevokedEntry[];
  /** CRL Number extension value as decimal string */
  crlNumber?: string;
  /** Authority Key Identifier as colon-separated hex */
  authorityKeyIdentifier?: string;
  /** Issuing Distribution Point URL(s), if present */
  issuingDistributionPoints?: string[];
  /** PEM-encoded CRL */
  raw: string;
  sourceFormat?: 'pem' | 'der';
}

// ─── CRL Viewer message protocol ─────────────────────────────────────────────

export type CrlViewerToExtMsg =
  | { type: 'crlViewerReady' }
  | { type: 'copyToClipboard'; value: string };

export type ExtToCrlViewerMsg =
  | { type: 'crlLoading' }
  | { type: 'crlData'; crl: CrlData }
  | { type: 'crlError'; message: string };

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
  signingMode: 'self-signed' | 'ca-signed' | 'csr';
  // P12 password (unused when signingMode === 'csr')
  password: string;
}

/**
 * Normalized subset of an OpenSSL `.cnf` config file used to pre-fill the
 * create-certificate form. Properties are present only when the CNF specifies them.
 * The five keyUsage* booleans are emitted together (all-or-nothing); same for eku*.
 */
export interface OpenSslConfig {
  // Subject DN (from [req_distinguished_name])
  cn?: string;
  o?: string;
  ou?: string;
  c?: string;
  st?: string;
  l?: string;
  email?: string;
  // SANs — newline-joined to match the form's textarea values
  dnsNames?: string;
  ipAddresses?: string;
  // Key
  keyAlgorithm?: KeyAlgorithm;   // derived from [req].default_bits
  defaultMd?: string;            // informational ([req].default_md), not consumed by generator
  validityDays?: number;         // [req].default_days
  // Extensions (see all-or-nothing contract above)
  isCA?: boolean;                // basicConstraints
  keyUsageDigitalSignature?: boolean;
  keyUsageKeyEncipherment?: boolean;
  keyUsageDataEncipherment?: boolean;
  keyUsageKeyCertSign?: boolean;
  keyUsageCRLSign?: boolean;
  ekuServerAuth?: boolean;
  ekuClientAuth?: boolean;
  ekuCodeSigning?: boolean;
  ekuEmailProtection?: boolean;
}

export type CreateCertToExtMsg =
  | { type: 'ready' }
  | { type: 'pickCaCert' }
  | { type: 'pickCaKey' }
  | { type: 'pickCnfFile' }
  | { type: 'saveCnfFile'; config: OpenSslConfig }
  | { type: 'saveDefaults'; config: OpenSslConfig }
  | { type: 'clearForm' }
  | { type: 'generate'; params: CertCreateParams }
  | { type: 'generateCsr'; params: CertCreateParams; keyPassword: string }
  | { type: 'saveCsrFile' }
  | { type: 'savePrivateKey' }
  | { type: 'cancel' }
  /** Response to 'requestInputDialog' from the extension; values is null if the user cancelled */
  | { type: 'inputDialogResponse'; requestId: string; values: Record<string, string> | null };

export type ExtToCreateCertMsg =
  | { type: 'caCertLoaded'; subject: string }
  | { type: 'caKeyLoaded'; description: string }
  | { type: 'cnfLoaded'; config: OpenSslConfig }
  | { type: 'defaultsLoaded'; config: OpenSslConfig }
  | { type: 'generating' }
  | { type: 'done' }
  | { type: 'csrReady'; csrPem: string }
  | { type: 'error'; message: string }
  /** Extension asks the webview to show a generic input dialog */
  | { type: 'requestInputDialog'; requestId: string; title: string; icon?: string; description?: string; fields: InputDialogFieldDef[]; confirmLabel?: string; cancelLabel?: string };

// ─── Generic input dialog ────────────────────────────────────────────────────

/** Field descriptor passed to the generic InputDialog webview component. */
export interface InputDialogFieldDef {
  /** Unique key used in the result map */
  id: string;
  /** Label shown above the input */
  label: string;
  /** Input type. 'select' renders a <select>; 'number'/'date' use native inputs */
  type?: 'text' | 'password' | 'number' | 'date' | 'select';
  /** Initial value */
  value?: string;
  /** Placeholder text */
  placeholder?: string;
  /** Options for type='select' */
  options?: Array<{ value: string; label: string }>;
  /** Mark field as required; empty value blocks submission */
  required?: boolean;
  /** Small hint rendered below the field */
  hint?: string;
  /** Minimum value / date string */
  min?: string;
  /** Maximum value / date string */
  max?: string;
  /** Step for type='number' */
  step?: number;
}

// ─── Message protocol ────────────────────────────────────────────────────────

export type ExtToWebviewMsg =
  | { type: 'loading'; status?: string }
  | { type: 'tlsProgress'; step: string }
  | { type: 'certificate'; chain: CertificateData[]; activeIndex: number; tlsSource?: TlsConnectionInfo }
  | { type: 'csr'; data: CsrData }
  | { type: 'error'; message: string }
  | { type: 'caIssuerCert'; cert: CertificateData; url: string }
  | { type: 'caIssuerError'; url: string; message: string }
  | { type: 'privateKeyImported'; certIndex: number; key: PrivateKeyInfo }
  | { type: 'privateKeyImportError'; certIndex: number; message: string }
  /** Extension asks the webview to show an in-panel passphrase dialog */
  | { type: 'requestPassphrase'; requestId: string; fileName: string; title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean }
  /** Extension asks the webview to show a generic input dialog */
  | { type: 'requestInputDialog'; requestId: string; title: string; icon?: string; description?: string; fields: InputDialogFieldDef[]; confirmLabel?: string; cancelLabel?: string };

export type WebviewToExtMsg =
  | { type: 'ready' }
  | { type: 'copyToClipboard'; value: string }
  | { type: 'selectCert'; index: number }
  | { type: 'downloadCaIssuer'; url: string }
  | { type: 'exportCert'; pem: string; suggestedName: string; format: 'pem' | 'der' }
  | { type: 'exportPrivateKey'; keyPem: string; suggestedName: string }
  | { type: 'createP12'; certPems: string[]; suggestedName: string; keyPem?: string }
  | { type: 'importPrivateKey'; certIndex: number; spkiPem: string }
  | { type: 'openCaCertFile'; topCertPem: string }
  | { type: 'signCsr'; csrPem: string }
  | { type: 'saveCsrFile' }
  | { type: 'savePrivateKey' }
  | { type: 'saveBothFiles'; suggestedName: string }
  /** Response to 'requestPassphrase'; passphrase is null if the user cancelled */
  | { type: 'passphraseResponse'; requestId: string; passphrase: string | null }
  /** Response to 'requestInputDialog'; values is null if the user cancelled */
  | { type: 'inputDialogResponse'; requestId: string; values: Record<string, string> | null }
  /** Opens the Format Conversion Hub panel */
  | { type: 'openConvertHub' };

// ─── Format Conversion Hub ───────────────────────────────────────────────────

export type ConvertToExtMsg =
  | { type: 'convertReady' }
  /** Pick a single file and store it under slotId */
  | { type: 'convertPickFile'; slotId: string; filters: Record<string, string[]> }
  /** Pick multiple files and store them under slotId_0, slotId_1, … */
  | { type: 'convertPickFiles'; slotId: string; filters: Record<string, string[]> }
  | { type: 'convertExecuteExtractP12'; passphrase: string; outputMode: 'individual' | 'bundle'; includeKey: boolean }
  | { type: 'convertExecuteBuildP12'; passphrase: string; includeKey: boolean }
  | { type: 'convertExecuteConvertFormat'; assetType: 'cert' | 'key'; direction: 'pem-to-der' | 'der-to-pem' }
  | { type: 'convertExecuteBundleChain'; orderedSlotIds: string[] };

export type ExtToConvertMsg =
  | { type: 'convertFileSelected'; slotId: string; fileName: string; fileCount?: number }
  | { type: 'convertResult'; message: string }
  | { type: 'convertError'; message: string };

// ─── Standalone Key Viewer ────────────────────────────────────────────────────

export interface StandaloneKeyData {
  /** 'private' or 'public' */
  kind: 'private' | 'public';
  /** Algorithm display name e.g. 'RSA', 'EC', 'Ed25519' */
  algorithm: string;
  /** RSA modulus length in bits */
  keySize?: number;
  /** EC named curve e.g. 'P-256' */
  namedCurve?: string;
  /** SHA-1 of SPKI DER, colon-separated uppercase hex (matches SubjectKeyIdentifier) */
  keyId: string;
  /** RSA modulus as colon-separated uppercase hex */
  modulus?: string;
  /** RSA public exponent as colon-separated uppercase hex */
  publicExponent?: string;
  /** True when the key file was passphrase-protected on disk */
  isEncrypted: boolean;
  /** Encoding/format as detected from the source file */
  inputFormat: 'pkcs8-pem' | 'encrypted-pkcs8-pem' | 'pkcs1-pem' | 'sec1-pem' | 'spki-pem' | 'pkcs1-pub-pem' | 'spki-der' | 'der' | 'unknown';
  /** SubjectPublicKeyInfo PEM (BEGIN PUBLIC KEY) */
  spkiPem: string;
  /** Unencrypted PKCS#8 PEM — present only for private keys */
  pkcs8Pem?: string;
}

export type KeyViewerToExtMsg =
  | { type: 'keyViewerReady' }
  | { type: 'copyToClipboard'; value: string }
  | { type: 'exportPrivateKey'; format: 'pkcs8-pem' | 'pkcs8-der' | 'pkcs1-pem' | 'pkcs1-der' | 'sec1-pem' | 'sec1-der'; encrypt: boolean; suggestedName: string }
  | { type: 'exportPublicKey'; format: 'spki-pem' | 'spki-der'; suggestedName: string }
  | { type: 'passphraseResponse'; requestId: string; passphrase: string | null }
  | { type: 'inputDialogResponse'; requestId: string; values: Record<string, string> | null };

export type ExtToKeyViewerMsg =
  | { type: 'keyLoading' }
  | { type: 'keyData'; key: StandaloneKeyData }
  | { type: 'keyError'; message: string }
  | { type: 'requestPassphrase'; requestId: string; fileName: string; title?: string; description?: string; buttonLabel?: string; requireConfirm?: boolean }
  | { type: 'requestInputDialog'; requestId: string; title: string; icon?: string; description?: string; fields: InputDialogFieldDef[]; confirmLabel?: string; cancelLabel?: string };

// ─── Key Generator ────────────────────────────────────────────────────────────

export type KeyGenToExtMsg =
  | { type: 'keyGenReady' }
  | { type: 'keyGenGenerate'; algorithm: KeyAlgorithm }
  | { type: 'keyGenSavePrivateKey' }
  | { type: 'keyGenSavePublicKey' }
  | { type: 'keyGenViewKey' }
  | { type: 'copyToClipboard'; value: string }
  | { type: 'inputDialogResponse'; requestId: string; values: Record<string, string> | null };

export type ExtToKeyGenMsg =
  | { type: 'keyGenGenerating' }
  | { type: 'keyGenDone'; key: StandaloneKeyData }
  | { type: 'keyGenError'; message: string }
  | { type: 'requestInputDialog'; requestId: string; title: string; icon?: string; description?: string; fields: InputDialogFieldDef[]; confirmLabel?: string; cancelLabel?: string };
