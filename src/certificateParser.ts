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
          }
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
