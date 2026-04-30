// QC Statements parser — OID 1.3.6.1.5.5.7.1.3
// ETSI EN 319 412-5 / RFC 3739

import { derTLV, derOid, derInt, derStr } from './derUtils';

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

export function parseQcStatements(rawData: ArrayBuffer | Uint8Array): string {
  const buf = rawData instanceof Uint8Array ? rawData : new Uint8Array(rawData);
  // buf = full Extension SEQUENCE: { OID, [BOOLEAN critical], OCTET STRING extnValue }
  const ext = derTLV(buf, 0);
  if (ext.tag !== 0x30) return '(invalid extension)';
  let off = 0;
  off = derTLV(ext.val, off).end;                            // skip extnID OID
  if (ext.val[off] === 0x01) off = derTLV(ext.val, off).end; // skip critical BOOLEAN
  const extnValue = derTLV(ext.val, off);                    // OCTET STRING
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
