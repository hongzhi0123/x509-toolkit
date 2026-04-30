import type { DistinguishedName } from './types';

export function bufToHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(':');
}

export function parseDNString(dn: string): DistinguishedName {
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
