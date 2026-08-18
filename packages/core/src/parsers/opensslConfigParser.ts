import type { KeyAlgorithm, OpenSslConfig } from '../types/types';

/**
 * A parsed OpenSSL config section: trimmed key → value.
 * Keys are stored exactly as written (case-sensitive); value lookup is
 * case-insensitive so `CN` / `cn` / `Cn` all resolve to the same field.
 */
type SectionMap = Record<string, string>;

/**
 * Remove an inline comment from a single (untrimmed) line.
 *
 * - `;` always starts a comment (INI-style).
 * - `#` starts a comment when it appears at the start of the line or after
 *   whitespace, so a `#` embedded in a value (e.g. `CN = foo#bar`) survives.
 */
function stripComment(line: string): string {
  let idx = line.indexOf(';');

  for (let i = 0; i < line.length; i++) {
    if (line[i] === '#' && (i === 0 || /\s/.test(line[i - 1]))) {
      if (idx === -1 || i < idx) idx = i;
      break;
    }
  }

  return idx >= 0 ? line.slice(0, idx) : line;
}

/** Remove a single pair of surrounding quotes (`"` or `'`). */
function unquote(value: string): string {
  if (value.length >= 2) {
    const first = value[0];
    const last = value[value.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return value.slice(1, -1);
    }
  }
  return value;
}

/**
 * Split a `key = value` or `key value` line into its parts.
 * Returns null when the line has no recognisable value.
 */
function splitKeyValue(line: string): { key: string; value: string } | null {
  const eq = line.indexOf('=');
  if (eq >= 0) {
    const key = line.slice(0, eq).trim();
    if (!key) return null;
    return { key, value: unquote(line.slice(eq + 1).trim()) };
  }

  const ws = line.match(/^(\S+)\s+(.*)$/);
  if (!ws) return null;
  return { key: ws[1].trim(), value: unquote(ws[2].trim()) };
}

/** First case-insensitive match for `key` within a section (insertion order). */
function getValue(sections: Record<string, SectionMap>, section: string, key: string): string | undefined {
  const sec = sections[section];
  if (!sec) return undefined;
  if (sec[key] !== undefined) return sec[key];

  const lower = key.toLowerCase();
  for (const k of Object.keys(sec)) {
    if (k.toLowerCase() === lower) return sec[k];
  }
  return undefined;
}

/**
 * Parse a `subjectAltName` value. Supports both the `@section` reference form
 * (`DNS.1` / `IP.1` … in the referenced section) and the inline form
 * (`DNS:example.com, IP:10.0.0.1`). Collected values are newline-joined.
 */
function parseSubjectAltName(
  san: string,
  sections: Record<string, SectionMap>,
): { dnsNames?: string; ipAddresses?: string } {
  const trimmed = san.trim();

  if (trimmed.startsWith('@')) {
    const ref = sections[trimmed.slice(1).trim()];
    if (!ref) return {};

    const dns: string[] = [];
    const ips: string[] = [];
    const entries: Array<{ idx: number; kind: 'dns' | 'ip'; value: string }> = [];

    for (const key of Object.keys(ref)) {
      const m = key.match(/^(DNS|IP)\.(\d+)$/i);
      if (!m) continue;
      entries.push({
        idx: parseInt(m[2], 10),
        kind: m[1].toLowerCase() === 'dns' ? 'dns' : 'ip',
        value: ref[key],
      });
    }

    entries.sort((a, b) => a.idx - b.idx);
    for (const e of entries) {
      if (e.kind === 'dns') dns.push(e.value);
      else ips.push(e.value);
    }

    return {
      ...(dns.length > 0 ? { dnsNames: dns.join('\n') } : {}),
      ...(ips.length > 0 ? { ipAddresses: ips.join('\n') } : {}),
    };
  }

  // Inline form: DNS:example.com, IP:10.0.0.1
  const dns: string[] = [];
  const ips: string[] = [];
  for (const part of trimmed.split(',')) {
    const token = part.trim();
    const m = token.match(/^(DNS|IP)\s*:\s*(.+)$/i);
    if (!m) continue;
    const value = m[2].trim();
    if (!value) continue;
    if (m[1].toLowerCase() === 'dns') dns.push(value);
    else ips.push(value);
  }

  return {
    ...(dns.length > 0 ? { dnsNames: dns.join('\n') } : {}),
    ...(ips.length > 0 ? { ipAddresses: ips.join('\n') } : {}),
  };
}

/**
 * Parse an OpenSSL-format config (`.cnf` / `.conf`) into the normalized
 * {@link OpenSslConfig} subset used to pre-fill the create-certificate form.
 *
 * Pure and non-throwing: unparseable lines and missing sections contribute
 * nothing, and a file with no recognised settings yields `{}`.
 */
export function parseOpenSslConfig(text: string): OpenSslConfig {
  const sections: Record<string, SectionMap> = {};
  let currentSection = '';

  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  for (const rawLine of lines) {
    const line = stripComment(rawLine).trim();
    if (!line) continue;

    const sectionMatch = line.match(/^\[\s*([^\]]+?)\s*\]$/);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim();
      if (!sections[currentSection]) sections[currentSection] = {};
      continue;
    }

    const kv = splitKeyValue(line);
    if (!kv) continue;
    if (!sections[currentSection]) sections[currentSection] = {};
    // First occurrence wins; later duplicates ignored.
    if (sections[currentSection][kv.key] === undefined) {
      sections[currentSection][kv.key] = kv.value;
    }
  }

  const result: OpenSslConfig = {};

  // ── Subject DN ──────────────────────────────────────────────────────────
  if (sections['req_distinguished_name']) {
    const cn = getValue(sections, 'req_distinguished_name', 'CN')
      ?? getValue(sections, 'req_distinguished_name', 'commonName');
    if (cn !== undefined) result.cn = cn;
    const o = getValue(sections, 'req_distinguished_name', 'O')
      ?? getValue(sections, 'req_distinguished_name', 'organizationName');
    if (o !== undefined) result.o = o;
    const ou = getValue(sections, 'req_distinguished_name', 'OU')
      ?? getValue(sections, 'req_distinguished_name', 'organizationalUnitName');
    if (ou !== undefined) result.ou = ou;
    const c = getValue(sections, 'req_distinguished_name', 'C')
      ?? getValue(sections, 'req_distinguished_name', 'countryName');
    if (c !== undefined) result.c = c;
    const st = getValue(sections, 'req_distinguished_name', 'ST')
      ?? getValue(sections, 'req_distinguished_name', 'stateOrProvinceName');
    if (st !== undefined) result.st = st;
    const l = getValue(sections, 'req_distinguished_name', 'L')
      ?? getValue(sections, 'req_distinguished_name', 'localityName');
    if (l !== undefined) result.l = l;
    const email = getValue(sections, 'req_distinguished_name', 'emailAddress');
    if (email !== undefined) result.email = email;
  }

  // ── Key / validity / hash ────────────────────────────────────────────────
  const bits = getValue(sections, 'req', 'default_bits');
  if (bits !== undefined) {
    const n = parseInt(bits, 10);
    if (!Number.isNaN(n)) {
      const keyAlgorithm: KeyAlgorithm = n === 4096 ? 'RSA-4096' : 'RSA-2048';
      result.keyAlgorithm = keyAlgorithm;
    }
  }

  const days = getValue(sections, 'req', 'default_days');
  if (days !== undefined) {
    const n = Number(days);
    if (Number.isInteger(n) && n > 0) result.validityDays = n;
  }

  const md = getValue(sections, 'req', 'default_md');
  if (md !== undefined) result.defaultMd = md;

  // ── Extensions ───────────────────────────────────────────────────────────
  const reqExtensions = getValue(sections, 'req', 'req_extensions');
  const extSectionName = (reqExtensions ?? 'v3_req').replace(/^@/, '').trim();
  const ext = sections[extSectionName];

  if (ext) {
    const bc = getValue(sections, extSectionName, 'basicConstraints');
    if (bc !== undefined) {
      result.isCA = /CA\s*:\s*TRUE/i.test(bc);
    }

    const keyUsage = getValue(sections, extSectionName, 'keyUsage');
    if (keyUsage !== undefined) {
      const tokens = keyUsage.split(',').map(t => t.trim().toLowerCase());
      // All-or-nothing: emit the whole boolean group when the line exists.
      result.keyUsageDigitalSignature = tokens.includes('digitalsignature');
      result.keyUsageKeyEncipherment = tokens.includes('keyencipherment');
      result.keyUsageDataEncipherment = tokens.includes('dataencipherment');
      result.keyUsageKeyCertSign = tokens.includes('keycertsign');
      result.keyUsageCRLSign = tokens.includes('crlsign'); // covers cRLSign & crlSign
    }

    const extendedKeyUsage = getValue(sections, extSectionName, 'extendedKeyUsage');
    if (extendedKeyUsage !== undefined) {
      const tokens = extendedKeyUsage.split(',').map(t => t.trim().toLowerCase());
      result.ekuServerAuth = tokens.includes('serverauth');
      result.ekuClientAuth = tokens.includes('clientauth');
      result.ekuCodeSigning = tokens.includes('codesigning');
      result.ekuEmailProtection = tokens.includes('emailprotection');
    }

    const subjectAltName = getValue(sections, extSectionName, 'subjectAltName');
    if (subjectAltName !== undefined) {
      const san = parseSubjectAltName(subjectAltName, sections);
      if (san.dnsNames !== undefined) result.dnsNames = san.dnsNames;
      if (san.ipAddresses !== undefined) result.ipAddresses = san.ipAddresses;
    }
  }

  return result;
}

/** Serialize form-compatible settings as a portable OpenSSL request config. */
export function serializeOpenSslConfig(config: OpenSslConfig): string {
  const lines = [
    '[ req ]',
    `default_bits = ${config.keyAlgorithm === 'RSA-4096' ? 4096 : 2048}`,
    'default_md = sha256',
    'prompt = no',
    'distinguished_name = req_distinguished_name',
    'req_extensions = req_ext',
    '',
    '[ req_distinguished_name ]',
  ];
  if (config.validityDays && Number.isInteger(config.validityDays) && config.validityDays > 0) {
    lines.splice(2, 0, `default_days = ${config.validityDays}`);
  }

  const dnFields: Array<[string, string | undefined]> = [
    ['countryName', config.c], ['stateOrProvinceName', config.st], ['localityName', config.l],
    ['organizationName', config.o], ['organizationalUnitName', config.ou], ['commonName', config.cn],
    ['emailAddress', config.email],
  ];
  for (const [name, value] of dnFields) {
    if (value?.trim()) lines.push(`${name} = ${value.trim()}`);
  }

  lines.push('', '[ req_ext ]', `basicConstraints = CA:${config.isCA ? 'TRUE' : 'FALSE'}`);

  const keyUsage = [
    config.keyUsageDigitalSignature && 'digitalSignature', config.keyUsageKeyEncipherment && 'keyEncipherment',
    config.keyUsageDataEncipherment && 'dataEncipherment', config.keyUsageKeyCertSign && 'keyCertSign',
    config.keyUsageCRLSign && 'cRLSign',
  ].filter((usage): usage is string => Boolean(usage));
  if (keyUsage.length > 0) lines.push(`keyUsage = ${keyUsage.join(', ')}`);

  const extendedKeyUsage = [
    config.ekuServerAuth && 'serverAuth', config.ekuClientAuth && 'clientAuth',
    config.ekuCodeSigning && 'codeSigning', config.ekuEmailProtection && 'emailProtection',
  ].filter((usage): usage is string => Boolean(usage));
  if (extendedKeyUsage.length > 0) lines.push(`extendedKeyUsage = ${extendedKeyUsage.join(', ')}`);

  const dnsNames = config.dnsNames?.split(/[\n,]/).map(name => name.trim()).filter(Boolean) ?? [];
  const ipAddresses = config.ipAddresses?.split(/[\n,]/).map(address => address.trim()).filter(Boolean) ?? [];
  if (dnsNames.length > 0 || ipAddresses.length > 0) {
    lines.push('subjectAltName = @alt_names', '', '[ alt_names ]');
    dnsNames.forEach((name, index) => lines.push(`DNS.${index + 1} = ${name}`));
    ipAddresses.forEach((address, index) => lines.push(`IP.${index + 1} = ${address}`));
  }

  return `${lines.join('\n')}\n`;
}
