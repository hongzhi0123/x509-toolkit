import { X509Crl, X509CrlReason, cryptoProvider } from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import type { CrlData, CrlRevokedEntry, DistinguishedName } from '../types/types';
import { bufToHex, parseDNString } from '../utils/certUtils';
import { SIG_ALG_NAMES } from '../types/oidMaps';

// Ensure the WebCrypto provider is initialised (idempotent).
cryptoProvider.set(new PeculiarCrypto());

// OID constants for CRL extensions
const OID_CRL_NUMBER = '2.5.29.20';
const OID_AUTHORITY_KEY_IDENTIFIER = '2.5.29.35';
const OID_ISSUING_DISTRIBUTION_POINT = '2.5.29.28';

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function parseCrlIssuerDn(nameStr: string): DistinguishedName {
  return parseDNString(nameStr);
}

/**
 * Try to detect PEM vs DER and return a raw DER Buffer.
 */
function normaliseToDer(input: Buffer): Buffer {
  const str = input.toString('ascii', 0, Math.min(input.length, 64));
  if (str.includes('-----BEGIN')) {
    // Strip PEM headers/footers and decode Base64
    const b64 = input
      .toString('utf8')
      .replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, '');
    return Buffer.from(b64, 'base64');
  }
  return input;
}

/**
 * Extract the CRL Number value (a non-negative integer) from DER-encoded
 * extension value. The extension value is an INTEGER wrapped in an OCTET STRING.
 * Raw extension data from @peculiar/x509 is the raw value bytes (after the OCTET STRING
 * wrapper), so we need to parse the INTEGER TLV.
 */
function parseCrlNumberFromRaw(rawData: ArrayBuffer): string {
  const bytes = new Uint8Array(rawData);
  // The rawData is the full extension value (DER INTEGER)
  // INTEGER tag = 0x02
  let off = 0;
  if (bytes[off] !== 0x02) return '';
  off++;
  let len = bytes[off++];
  if (len > 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | bytes[off++];
  }
  // Read the integer bytes (big-endian, possibly with leading 0x00 sign byte)
  let val = BigInt(0);
  for (let i = 0; i < len; i++) {
    val = (val << BigInt(8)) | BigInt(bytes[off + i]);
  }
  return val.toString();
}

/**
 * Extract the Subject Key Identifier hex from the AKI extension raw DER bytes.
 * AKI SEQUENCE { [0] OCTET STRING (keyIdentifier) }
 */
function parseAkiFromRaw(rawData: ArrayBuffer): string {
  const bytes = new Uint8Array(rawData);
  // SEQUENCE { [0] IMPLICIT OCTET STRING }
  let off = 0;
  if (bytes[off] !== 0x30) return '';
  off++;
  // Skip length
  let seqLen = bytes[off++];
  if (seqLen > 0x80) { const n = seqLen & 0x7f; off += n; }

  // Expect [0] (0x80) context tag for keyIdentifier
  if (off >= bytes.length || bytes[off] !== 0x80) return '';
  off++;
  let kidLen = bytes[off++];
  if (kidLen > 0x80) {
    const n = kidLen & 0x7f;
    kidLen = 0;
    for (let i = 0; i < n; i++) kidLen = (kidLen << 8) | bytes[off++];
  }
  return bufToHex(Buffer.from(bytes.slice(off, off + kidLen)));
}

// ------------------------------------------------------------------
// Main export
// ------------------------------------------------------------------

/**
 * Parse a PEM- or DER-encoded Certificate Revocation List (CRL) and return
 * a {@link CrlData} object suitable for display in the webview.
 *
 * Throws if the input cannot be parsed as a valid CRL.
 */
export function parseCrl(input: Buffer): CrlData {
  const der = normaliseToDer(input);
  const isPem = input.toString('ascii', 0, Math.min(input.length, 64)).includes('-----BEGIN');

  let crl: X509Crl;
  try {
    // Buffer's underlying ArrayBufferLike may be SharedArrayBuffer; slice to guarantee ArrayBuffer.
    const ab = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength) as ArrayBuffer;
    crl = new X509Crl(ab);
  } catch (e) {
    throw new Error(`Failed to parse CRL: ${(e as Error).message ?? String(e)}`);
  }

  // ── Issuer ──────────────────────────────────────────────────────
  const issuer = parseCrlIssuerDn(crl.issuerName.toString());

  // ── Dates ───────────────────────────────────────────────────────
  const thisUpdate = crl.thisUpdate.toISOString();
  const nextUpdate = crl.nextUpdate ? crl.nextUpdate.toISOString() : undefined;
  const isExpired = nextUpdate ? new Date(nextUpdate) < new Date() : false;

  // ── Signature algorithm ─────────────────────────────────────────
  const sigAlgOid = crl.signatureAlgorithm.name ?? '';
  const signatureAlgorithm = SIG_ALG_NAMES[sigAlgOid] ?? sigAlgOid;

  // ── Revoked entries ─────────────────────────────────────────────
  const revokedCertificates: CrlRevokedEntry[] = crl.entries.map(entry => {
    const item: CrlRevokedEntry = {
      serialNumber: entry.serialNumber,
      revocationDate: entry.revocationDate.toISOString(),
    };

    if (entry.reason !== undefined && entry.reason !== null) {
      const reasonStr = X509CrlReason[entry.reason as number];
      if (reasonStr) item.reason = reasonStr;
    }

    if (entry.invalidity) {
      item.invalidityDate = entry.invalidity.toISOString();
    }

    return item;
  });

  // ── CRL extensions ───────────────────────────────────────────────
  let crlNumber: string | undefined;
  let authorityKeyIdentifier: string | undefined;
  const issuingDistributionPoints: string[] = [];

  for (const ext of crl.extensions ?? []) {
    try {
      if (ext.type === OID_CRL_NUMBER) {
        crlNumber = parseCrlNumberFromRaw(ext.rawData);
      } else if (ext.type === OID_AUTHORITY_KEY_IDENTIFIER) {
        const aki = parseAkiFromRaw(ext.rawData);
        if (aki) authorityKeyIdentifier = aki;
      } else if (ext.type === OID_ISSUING_DISTRIBUTION_POINT) {
        // Best-effort: just note presence
        issuingDistributionPoints.push('(present — details omitted)');
      }
    } catch { /* ignore extension parse errors */ }
  }

  // ── Version ─────────────────────────────────────────────────────
  const version = (crl.version ?? 1) + 1; // @peculiar uses 0-based (0=v1, 1=v2)

  // ── PEM output ──────────────────────────────────────────────────
  const rawPem = isPem
    ? input.toString('utf8')
    : `-----BEGIN X509 CRL-----\n${der.toString('base64').match(/.{1,64}/g)!.join('\n')}\n-----END X509 CRL-----\n`;

  const result: CrlData = {
    version,
    issuer,
    signatureAlgorithm,
    thisUpdate,
    nextUpdate,
    isExpired,
    revokedCertificates,
    raw: rawPem,
    sourceFormat: isPem ? 'pem' : 'der',
  };

  if (crlNumber !== undefined) result.crlNumber = crlNumber;
  if (authorityKeyIdentifier !== undefined) result.authorityKeyIdentifier = authorityKeyIdentifier;
  if (issuingDistributionPoints.length > 0) result.issuingDistributionPoints = issuingDistributionPoints;

  return result;
}

/**
 * Parse one or more PEM-encoded CRLs from a single buffer.
 * Returns an array; each `-----BEGIN X509 CRL-----` block becomes one entry.
 */
export function parsePemCrlChain(input: Buffer): CrlData[] {
  const text = input.toString('utf8');
  const blocks = [...text.matchAll(/-----BEGIN X509 CRL-----[\s\S]*?-----END X509 CRL-----/g)];
  if (blocks.length === 0) {
    // Try as a single CRL (PEM or DER)
    return [parseCrl(input)];
  }
  return blocks.map(m => parseCrl(Buffer.from(m[0], 'utf8')));
}
