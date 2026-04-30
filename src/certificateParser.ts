import {
  X509Certificate,
  cryptoProvider,
  SubjectAlternativeNameExtension,
  BasicConstraintsExtension,
  KeyUsagesExtension,
  KeyUsageFlags,
  ExtendedKeyUsageExtension,
  SubjectKeyIdentifierExtension,
  AuthorityKeyIdentifierExtension,
  CRLDistributionPointsExtension,
  AuthorityInfoAccessExtension,
} from '@peculiar/x509';
import { Crypto as PeculiarCrypto } from '@peculiar/webcrypto';
import type {
  CertificateData,
  CertExtension,
  DistinguishedName,
  PublicKeyInfo,
} from './types';

// ------------------------------------------------------------------
// Bootstrap @peculiar/webcrypto as the WebCrypto provider for Node.js
// ------------------------------------------------------------------
const cryptoImpl = new PeculiarCrypto();
cryptoProvider.set(cryptoImpl);

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function bufToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':');
}

function parseDNString(dn: string): DistinguishedName {
  const result: DistinguishedName = { raw: dn };
  // Walk attribute=value pairs; commas inside quotes or after backslash are escaped
  const pairs = dn.split(/,(?![^,]*\\)/);
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx < 0) continue;
    const key = pair.slice(0, eqIdx).trim().toUpperCase();
    const val = pair.slice(eqIdx + 1).trim();
    switch (key) {
      case 'CN':           result.commonName = val; break;
      case 'O':            result.organization = val; break;
      case 'OU':           result.organizationalUnit = val; break;
      case 'C':            result.country = val; break;
      case 'ST':
      case 'S':            result.state = val; break;
      case 'L':            result.locality = val; break;
      case 'E':
      case 'EMAILADDRESS': result.email = val; break;
      case 'DC':           result.domainComponent = val; break;
      case 'UID':          result.userId = val; break;
    }
  }
  return result;
}

// ------------------------------------------------------------------
// Extension OID name maps
// ------------------------------------------------------------------

const EXT_NAMES: Record<string, string> = {
  '2.5.29.9':  'Subject Directory Attributes',
  '2.5.29.14': 'Subject Key Identifier',
  '2.5.29.15': 'Key Usage',
  '2.5.29.16': 'Private Key Usage Period',
  '2.5.29.17': 'Subject Alternative Names',
  '2.5.29.18': 'Issuer Alternative Name',
  '2.5.29.19': 'Basic Constraints',
  '2.5.29.20': 'CRL Number',
  '2.5.29.21': 'Reason Code',
  '2.5.29.23': 'Hold Instruction Code',
  '2.5.29.24': 'Invalidity Date',
  '2.5.29.27': 'Delta CRL Indicator',
  '2.5.29.28': 'Issuing Distribution Point',
  '2.5.29.29': 'Certificate Issuer',
  '2.5.29.30': 'Name Constraints',
  '2.5.29.31': 'CRL Distribution Points',
  '2.5.29.32': 'Certificate Policies',
  '2.5.29.33': 'Policy Mappings',
  '2.5.29.35': 'Authority Key Identifier',
  '2.5.29.36': 'Policy Constraints',
  '2.5.29.37': 'Extended Key Usage',
  '2.5.29.46': 'Freshest CRL',
  '2.5.29.54': 'Inhibit Any Policy',
  '1.3.6.1.5.5.7.1.1':  'Authority Information Access',
  '1.3.6.1.5.5.7.1.3':  'QC Statements',
  '1.3.6.1.5.5.7.1.11': 'Subject Information Access',
  '0.4.0.19495.2':        'PSD2 QcStatement',
  '1.3.6.1.4.1.11129.2.4.2': 'Certificate Transparency SCTs',
  '1.3.6.1.4.1.11129.2.4.3': 'CT Poison',
};

const EKU_NAMES: Record<string, string> = {
  '1.3.6.1.5.5.7.3.1': 'TLS Server Authentication',
  '1.3.6.1.5.5.7.3.2': 'TLS Client Authentication',
  '1.3.6.1.5.5.7.3.3': 'Code Signing',
  '1.3.6.1.5.5.7.3.4': 'Email Protection',
  '1.3.6.1.5.5.7.3.8': 'Time Stamping',
  '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
  '2.5.29.37.0':        'Any Extended Key Usage',
  '1.3.6.1.4.1.311.10.3.3': 'Microsoft SGC',
  '2.16.840.1.113730.4.1':  'Netscape SGC',
};

const SIG_ALG_NAMES: Record<string, string> = {
  '1.2.840.113549.1.1.4':  'MD5 with RSA',
  '1.2.840.113549.1.1.5':  'SHA-1 with RSA',
  '1.2.840.113549.1.1.11': 'SHA-256 with RSA',
  '1.2.840.113549.1.1.12': 'SHA-384 with RSA',
  '1.2.840.113549.1.1.13': 'SHA-512 with RSA',
  '1.2.840.113549.1.1.10': 'RSASSA-PSS',
  '1.2.840.10045.4.3.1': 'ECDSA with SHA-224',
  '1.2.840.10045.4.3.2': 'ECDSA with SHA-256',
  '1.2.840.10045.4.3.3': 'ECDSA with SHA-384',
  '1.2.840.10045.4.3.4': 'ECDSA with SHA-512',
  '1.3.101.112': 'Ed25519',
  '1.3.101.113': 'Ed448',
};

// ------------------------------------------------------------------
// Minimal DER TLV reader  (used for bespoke extension parsing)
// ------------------------------------------------------------------

function derTLV(buf: Uint8Array, off: number): { tag: number; val: Uint8Array; end: number } {
  const tag = buf[off++];
  let b = buf[off++];
  let len: number;
  if (b < 0x80) {
    len = b;
  } else {
    const n = b & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off++];
  }
  return { tag, val: buf.subarray(off, off + len), end: off + len };
}

function derOid(b: Uint8Array): string {
  if (!b.length) return '';
  const c: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  let acc = 0;
  for (let i = 1; i < b.length; i++) {
    acc = (acc << 7) | (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { c.push(acc); acc = 0; }
  }
  return c.join('.');
}

function derInt(b: Uint8Array): number {
  if (!b.length) return 0;
  let v = b[0] & 0x80 ? b[0] - 256 : b[0];
  for (let i = 1; i < b.length; i++) v = v * 256 + b[i];
  return v;
}

function derStr(b: Uint8Array): string {
  return Buffer.from(b).toString('utf8');
}

// ------------------------------------------------------------------
// QC Statements parser  (OID 1.3.6.1.5.5.7.1.3)
// ETSI EN 319 412-5 / RFC 3739
// ------------------------------------------------------------------

const PSD2_ROLE_NAMES: Record<string, string> = {
  '0.4.0.19495.1.1': 'PSP_AS (Account Servicing)',
  '0.4.0.19495.1.2': 'PSP_PI (Payment Initiation)',
  '0.4.0.19495.1.3': 'PSP_AI (Account Information)',
  '0.4.0.19495.1.4': 'PSP_IC (Card-Based Payment Instruments)',
};

const QCS_NAMES: Record<string, string> = {
  '0.4.0.1862.1.1': 'QcCompliance',
  '0.4.0.19495.2':  'PSD2 QcStatement',
  '0.4.0.1862.1.2': 'QcLimitValue',
  '0.4.0.1862.1.3': 'QcRetentionPeriod',
  '0.4.0.1862.1.4': 'QcSSCD',
  '0.4.0.1862.1.5': 'QcPDS',
  '0.4.0.1862.1.6': 'QcType',
  '0.4.0.1862.1.7': 'QcCClegislation',
  '1.3.6.1.5.5.7.11.1': 'QcSyntax-v1',
  '1.3.6.1.5.5.7.11.2': 'QcSyntax-v2',
};

const QC_TYPE_NAMES: Record<string, string> = {
  '0.4.0.1862.1.6.1': 'Electronic Signature (eSign)',
  '0.4.0.1862.1.6.2': 'Electronic Seal (eSeal)',
  '0.4.0.1862.1.6.3': 'Website Authentication (Web)',
};

const QC_SEMANTICS_NAMES: Record<string, string> = {
  '0.4.0.1862.1.1.1': 'Natural Person',
  '0.4.0.1862.1.1.2': 'Legal Person',
};

function fmtQcStatement(oid: string, label: string, info: Uint8Array): string {
  if (!info.length) {
    switch (oid) {
      case '0.4.0.1862.1.1':
        return `\u2022 ${label}: Certificate conforms to EU eIDAS Regulation`;
      case '0.4.0.1862.1.4':
        return `\u2022 ${label}: Private key stored on SSCD/QSCD`;
      default:
        return `\u2022 ${label}`;
    }
  }
  try {
    switch (oid) {
      case '0.4.0.1862.1.2': { // QcLimitValue: MonetaryValue { Iso4217, amount INT, exponent INT }
        const seq = derTLV(info, 0);
        let o = 0;
        const cTlv = derTLV(seq.val, o); o = cTlv.end;
        const aTlv = derTLV(seq.val, o); o = aTlv.end;
        const eTlv = derTLV(seq.val, o);
        const currency = (cTlv.tag === 0x13 || cTlv.tag === 0x0c)
          ? derStr(cTlv.val)
          : `ISO-4217 #${derInt(cTlv.val)}`;
        const value = derInt(aTlv.val) * Math.pow(10, derInt(eTlv.val));
        return `\u2022 ${label}: ${value.toLocaleString()} ${currency}`;
      }
      case '0.4.0.1862.1.3': { // QcRetentionPeriod: INTEGER (years)
        const t = derTLV(info, 0);
        return `\u2022 ${label}: ${derInt(t.val)} year(s)`;
      }
      case '0.4.0.1862.1.5': { // QcPDS: SEQUENCE OF PDSLocation { url IA5String, lang PrintableString }
        const outer = derTLV(info, 0);
        const locs: string[] = [];
        let o = 0;
        while (o < outer.val.length) {
          const loc  = derTLV(outer.val, o); o = loc.end;
          const url  = derTLV(loc.val, 0);
          const lang = derTLV(loc.val, url.end);
          locs.push(`[${derStr(lang.val).toUpperCase()}] ${derStr(url.val)}`);
        }
        return `\u2022 ${label}:\n${locs.map(l => `  ${l}`).join('\n')}`;
      }
      case '0.4.0.1862.1.6': { // QcType: SEQUENCE { (SEQUENCE OF OID | direct OIDs) }
        const outer = derTLV(info, 0);
        const types: string[] = [];
        const content = outer.val;
        // Some encodings nest a SEQUENCE OF OID, others list OIDs directly
        let src = content;
        if (content.length > 0 && content[0] === 0x30) {
          src = derTLV(content, 0).val;
        }
        let o = 0;
        while (o < src.length) {
          const t = derTLV(src, o); o = t.end;
          if (t.tag === 0x06) types.push(QC_TYPE_NAMES[derOid(t.val)] ?? derOid(t.val));
        }
        return `\u2022 ${label}: ${types.join(', ')}`;
      }
      case '0.4.0.1862.1.7': { // QcCClegislation: SEQUENCE OF PrintableString (2-letter country codes)
        const seq = derTLV(info, 0);
        const codes: string[] = [];
        let o = 0;
        while (o < seq.val.length) {
          const s = derTLV(seq.val, o); o = s.end;
          codes.push(derStr(s.val));
        }
        return `\u2022 ${label}: ${codes.join(', ')}`;
      }
      case '0.4.0.19495.2': { // PSD2QcType ::= SEQUENCE { rolesOfPSP, nCAName, nCAId }
        const top = derTLV(info, 0);
        let p = 0;
        // rolesOfPSP: SEQUENCE OF RoleOfPSP
        const rolesSEQ = derTLV(top.val, p); p = rolesSEQ.end;
        const roles: string[] = [];
        let rp = 0;
        while (rp < rolesSEQ.val.length) {
          const roleSeq = derTLV(rolesSEQ.val, rp); rp = roleSeq.end;
          if (roleSeq.tag !== 0x30) continue;
          const roleOidTlv = derTLV(roleSeq.val, 0);
          const roleOid = derOid(roleOidTlv.val);
          roles.push(PSD2_ROLE_NAMES[roleOid] ?? derStr(derTLV(roleSeq.val, roleOidTlv.end).val));
        }
        // nCAName: UTF8String
        const ncaNameTlv = derTLV(top.val, p); p = ncaNameTlv.end;
        const ncaName = derStr(ncaNameTlv.val);
        // nCAId: UTF8String
        const ncaIdTlv = derTLV(top.val, p);
        const ncaId = derStr(ncaIdTlv.val);
        return `\u2022 ${label}:\n${roles.map(r => `    \u2022 ${r}`).join('\n')}\n  NCA: ${ncaName} (${ncaId})`;
      }
      case '1.3.6.1.5.5.7.11.1':
      case '1.3.6.1.5.5.7.11.2': { // SemanticsInformation { semanticsId OID OPTIONAL, ... }
        const seq = derTLV(info, 0);
        const parts: string[] = [];
        let o = 0;
        while (o < seq.val.length) {
          const t = derTLV(seq.val, o); o = t.end;
          if (t.tag === 0x06) {
            const sid = derOid(t.val);
            parts.push(QC_SEMANTICS_NAMES[sid] ?? sid);
          }
        }
        return `\u2022 ${label}${parts.length ? ': ' + parts.join(', ') : ''}`;
      }
      default:
        return `\u2022 ${label}`;
    }
  } catch {
    return `\u2022 ${label}`;
  }
}

function parseQcStatements(rawData: ArrayBuffer | Uint8Array): string {
  const buf = rawData instanceof Uint8Array ? rawData : new Uint8Array(rawData);
  // buf = full Extension SEQUENCE: { OID, [BOOLEAN critical], OCTET STRING extnValue }
  const ext = derTLV(buf, 0);
  if (ext.tag !== 0x30) return '(invalid extension)';
  let off = 0;
  off = derTLV(ext.val, off).end;                          // skip extnID OID
  if (ext.val[off] === 0x01) off = derTLV(ext.val, off).end; // skip critical BOOLEAN
  const extnValue = derTLV(ext.val, off);                  // OCTET STRING
  if (extnValue.tag !== 0x04) return '(expected OCTET STRING)';

  // QCStatements ::= SEQUENCE OF QCStatement
  const outer = derTLV(extnValue.val, 0);
  if (outer.tag !== 0x30) return '(expected SEQUENCE OF)';

  const lines: string[] = [];
  let stmtOff = 0;
  while (stmtOff < outer.val.length) {
    const stmt = derTLV(outer.val, stmtOff);
    stmtOff = stmt.end;
    if (stmt.tag !== 0x30) continue;
    const oidTlv = derTLV(stmt.val, 0);
    const oid    = derOid(oidTlv.val);
    const label  = QCS_NAMES[oid] ?? oid;
    lines.push(fmtQcStatement(oid, label, stmt.val.subarray(oidTlv.end)));
  }
  return lines.join('\n') || '(empty)';
}

// ------------------------------------------------------------------
// Extension parser
// ------------------------------------------------------------------

function parseExtensions(cert: X509Certificate): CertExtension[] {
  const result: CertExtension[] = [];
  for (const ext of cert.extensions) {
    const item: CertExtension = {
      oid: ext.type,
      name: EXT_NAMES[ext.type] ?? ext.type,
      critical: ext.critical,
      value: '',
      raw: bufToHex(ext.rawData),
    };
    try {
      switch (ext.type) {
        case '2.5.29.17': { // SAN
          const san = cert.getExtension(SubjectAlternativeNameExtension);
          if (san) {
            item.value = san.names.items
              .map(n => `${n.type.toUpperCase()}: ${n.value}`)
              .join('\n');
          }
          break;
        }
        case '2.5.29.19': { // Basic Constraints
          const bc = cert.getExtension(BasicConstraintsExtension);
          if (bc) {
            item.value = `CA: ${bc.ca}`;
            if (bc.pathLength !== undefined) item.value += `, Path Length: ${bc.pathLength}`;
          }
          break;
        }
        case '2.5.29.15': { // Key Usage
          const ku = cert.getExtension(KeyUsagesExtension);
          if (ku) {
            const usages: string[] = [];
            if (ku.usages & KeyUsageFlags.digitalSignature) usages.push('Digital Signature');
            if (ku.usages & KeyUsageFlags.nonRepudiation)   usages.push('Non-Repudiation');
            if (ku.usages & KeyUsageFlags.keyEncipherment)  usages.push('Key Encipherment');
            if (ku.usages & KeyUsageFlags.dataEncipherment) usages.push('Data Encipherment');
            if (ku.usages & KeyUsageFlags.keyAgreement)     usages.push('Key Agreement');
            if (ku.usages & KeyUsageFlags.keyCertSign)      usages.push('Key Cert Sign');
            if (ku.usages & KeyUsageFlags.cRLSign)          usages.push('CRL Sign');
            if (ku.usages & KeyUsageFlags.encipherOnly)     usages.push('Encipher Only');
            if (ku.usages & KeyUsageFlags.decipherOnly)     usages.push('Decipher Only');
            item.value = usages.join(', ');
          }
          break;
        }
        case '2.5.29.37': { // Extended Key Usage
          const eku = cert.getExtension(ExtendedKeyUsageExtension);
          if (eku) {
            item.value = eku.usages.map(oid => EKU_NAMES[String(oid)] ?? String(oid)).join('\n');
          }
          break;
        }
        case '2.5.29.14': { // Subject Key Identifier
          const ski = cert.getExtension(SubjectKeyIdentifierExtension);
          if (ski) item.value = ski.keyId;
          break;
        }
        case '2.5.29.35': { // Authority Key Identifier
          const aki = cert.getExtension(AuthorityKeyIdentifierExtension);
          if (aki) {
            const parts: string[] = [];
            if (aki.keyId) parts.push(`Key ID: ${aki.keyId}`);
            if (aki.certId?.serialNumber) parts.push(`Serial: ${aki.certId.serialNumber}`);
            item.value = parts.join('\n') || 'Present';
          }
          break;
        }
        case '2.5.29.31': { // CRL Distribution Points
          const cdp = cert.getExtension(CRLDistributionPointsExtension);
          if (cdp) {
            const urls: string[] = [];
            for (const point of cdp.distributionPoints) {
              if (point.distributionPoint?.fullName) {
                for (const n of point.distributionPoint.fullName) {
                  // n is asn1-x509 GeneralName; URI is in uniformResourceIdentifier
                  const uri = (n as any).uniformResourceIdentifier ?? (n as any).value;
                  if (uri) urls.push(String(uri));
                }
              }
            }
            item.value = urls.join('\n');
          }
          break;
        }
        case '1.3.6.1.5.5.7.1.1': { // Authority Information Access
          const aia = cert.getExtension(AuthorityInfoAccessExtension);
          if (aia) {
            const parts: string[] = [];
            for (const n of aia.ocsp)      parts.push(`OCSP: ${n.value}`);
            for (const n of aia.caIssuers) parts.push(`CA Issuers: ${n.value}`);
            item.value = parts.join('\n');
            item.caIssuerUrls = aia.caIssuers
              .map(n => String(n.value))
              .filter(u => u.startsWith('http://') || u.startsWith('https://'));
          }
          break;
        }
        case '1.3.6.1.5.5.7.1.3': { // QC Statements (ETSI EN 319 412-5)
          item.value = parseQcStatements(ext.rawData);
          break;
        }
        default:
          item.value = '(see raw hex)';
      }
    } catch {
      item.value = '(parse error — see raw hex)';
    }
    result.push(item);
  }
  return result;
}

// ------------------------------------------------------------------
// Public key info
// ------------------------------------------------------------------

async function buildPublicKeyInfo(cert: X509Certificate): Promise<PublicKeyInfo> {
  const pubKey = cert.publicKey;
  const spki = bufToHex(pubKey.rawData);
  try {
    const cryptoKey = await pubKey.export(cryptoImpl);
    const alg = cryptoKey.algorithm as { name: string; modulusLength?: number; namedCurve?: string };
    return {
      algorithm: alg.name,
      keySize: alg.modulusLength,
      namedCurve: alg.namedCurve,
      spki,
    };
  } catch {
    return { algorithm: 'Unknown', spki };
  }
}

function sigAlgName(cert: X509Certificate): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const oid: string = (cert.signatureAlgorithm as any)?.algorithm?.value ?? '';
  return SIG_ALG_NAMES[oid] ?? (oid || 'Unknown');
}

// ------------------------------------------------------------------
// Main exported functions
// ------------------------------------------------------------------

export async function parseCertificate(input: string | Buffer): Promise<CertificateData> {
  let cert: X509Certificate;

  if (typeof input === 'string') {
    const trimmed = input.trim();
    if (trimmed.includes('-----BEGIN CERTIFICATE-----')) {
      const match = trimmed.match(
        /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/
      );
      if (!match) throw new Error('Malformed PEM: could not find certificate block.');
      cert = new X509Certificate(match[0]);
    } else {
      // Possibly base64-encoded DER
      const der = Buffer.from(trimmed.replace(/\s+/g, ''), 'base64');
      cert = new X509Certificate(der);
    }
  } else {
    cert = new X509Certificate(input);
  }

  const now = new Date();
  const daysRemaining = Math.floor(
    (cert.notAfter.getTime() - now.getTime()) / 86_400_000
  );

  const [sha1, sha256, pubKeyInfo] = await Promise.all([
    cert.getThumbprint('SHA-1', cryptoImpl),
    cert.getThumbprint('SHA-256', cryptoImpl),
    buildPublicKeyInfo(cert),
  ]);

  // Format serial number with colons
  const rawSerial = cert.serialNumber.length % 2 === 0
    ? cert.serialNumber
    : '0' + cert.serialNumber;
  const serialNumber = rawSerial.replace(/(.{2})/g, '$1:').replace(/:$/, '').toUpperCase();

  let isCA = false;
  try {
    const bc = cert.getExtension(BasicConstraintsExtension);
    isCA = bc?.ca ?? false;
  } catch { /* ignore */ }

  return {
    version: ((cert as any).asn?.tbsCertificate?.version ?? 2) + 1,
    serialNumber,
    subject: parseDNString(cert.subject),
    issuer:  parseDNString(cert.issuer),
    validity: {
      notBefore:    cert.notBefore.toISOString(),
      notAfter:     cert.notAfter.toISOString(),
      isExpired:    cert.notAfter < now,
      daysRemaining,
    },
    publicKey: pubKeyInfo,
    signature: {
      algorithm: sigAlgName(cert),
      value: bufToHex(cert.signature),
    },
    extensions:   parseExtensions(cert),
    fingerprints: {
      sha1:   bufToHex(sha1).toUpperCase(),
      sha256: bufToHex(sha256).toUpperCase(),
    },
    raw:          cert.toString('pem'),
    isCA,
    isSelfSigned: cert.subject === cert.issuer,
  };
}

/** Parse all certificates from a PEM chain, returning them in order. */
export async function parsePEMChain(pem: string): Promise<CertificateData[]> {
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const blocks = pem.match(regex);
  if (!blocks?.length) throw new Error('No certificate blocks found in the input.');
  return Promise.all(blocks.map(b => parseCertificate(b)));
}
