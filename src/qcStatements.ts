// QC Statements extension — OID 1.3.6.1.5.5.7.1.3
// Follows the @peculiar/x509 Extension subclass pattern.
// Standards: ETSI EN 319 412-5, RFC 3739, ETSI TS 119 495 (PSD2)

import { AsnConvert, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, AsnArray } from '@peculiar/asn1-schema';
import { Extension as AsnX509Extension } from '@peculiar/asn1-x509';
import { Extension, ExtensionFactory } from '@peculiar/x509';
import {
  id_pe_qcStatements,
  QCStatements,
  SemanticsInformation,
  id_qcs_pkixQCSyntax_v1,
  id_qcs_pkixQCSyntax_v2,
} from '@peculiar/asn1-x509-qualified';
import {
  id_etsi_qcs_qcCompliance,
  id_etsi_qcs_qcType,
  id_etsi_qct_web,
  id_etsi_qcs_qcPDS,
  id_etsi_qcs_qcCClegislation,
  id_etsi_qcs_qcSSCD,
  id_etsi_qcs_qcLimitValue,
  id_etsi_qcs_qcRetentionPeriod,
  id_etsi_qct_eseal,
  id_etsi_qct_esign,
  QcCClegislation,
  QcType,
  QcEuPDS,
  QcEuRetentionPeriod,
  MonetaryValue
} from '@peculiar/asn1-x509-qualified-etsi';
import { derTLV } from './derUtils'; // used only in the backward-compat shim

// ── OID constants ─────────────────────────────────────────────────────────────
// const id_etsi_qcs                 = '0.4.0.1862.1';
// const id_etsi_qcs_QcCompliance    = `${id_etsi_qcs}.1`;
// const id_etsi_qcs_QcLimitValue    = `${id_etsi_qcs}.2`;
// const id_etsi_qcs_QcRetention     = `${id_etsi_qcs}.3`;
// const id_etsi_qcs_QcSSCD          = `${id_etsi_qcs}.4`;
// const id_etsi_qcs_QcPDS           = `${id_etsi_qcs}.5`;
// const id_etsi_qcs_QcType          = `${id_etsi_qcs}.6`;
// const id_etsi_qcs_QcCClegislation = `${id_etsi_qcs}.7`;
const id_etsi_psd2                = '0.4.0.19495.2';

// ── Name lookup tables ────────────────────────────────────────────────────────
const PSD2_ROLE_NAMES: Record<string, string> = {
  '0.4.0.19495.1.1': 'PSP_AS (Account Servicing)',
  '0.4.0.19495.1.2': 'PSP_PI (Payment Initiation)',
  '0.4.0.19495.1.3': 'PSP_AI (Account Information)',
  '0.4.0.19495.1.4': 'PSP_IC (Card-Based Payment Instruments)',
};

const QC_TYPE_NAMES: Record<string, string> = {
  [id_etsi_qct_esign]: 'Electronic Signature (eSign)',
  [id_etsi_qct_eseal]: 'Electronic Seal (eSeal)',
  [id_etsi_qct_web]: 'Website Authentication (Web)',
};

const QC_SEMANTICS_NAMES: Record<string, string> = {
  '0.4.0.1862.1.1.1': 'Natural Person',
  '0.4.0.1862.1.1.2': 'Legal Person',
};

// ── ASN.1 structure definitions (ETSI EN 319 412-5 / ETSI TS 119 495) ─────────

// // Iso4217CurrencyCode ::= CHOICE { alphabetic PrintableString, numeric INTEGER }
// // Lenient: also accepts Utf8String for non-conformant certificates.
// @AsnType({ type: AsnTypeTypes.Choice })
// class Iso4217CurrencyCode {
//   @AsnProp({ type: AsnPropTypes.PrintableString })
//   alphabetic?: string;

//   @AsnProp({ type: AsnPropTypes.Utf8String })
//   alphabeticUtf8?: string;

//   @AsnProp({ type: AsnPropTypes.Integer })
//   numeric?: number;
// }

// // MonetaryValue ::= SEQUENCE { currency Iso4217CurrencyCode, amount INTEGER, exponent INTEGER }
// class MonetaryValue {
//   @AsnProp({ type: Iso4217CurrencyCode })
//   currency = new Iso4217CurrencyCode();

//   @AsnProp({ type: AsnPropTypes.Integer })
//   amount = 0;

//   @AsnProp({ type: AsnPropTypes.Integer })
//   exponent = 0;
// }

// // QcRetentionPeriod ::= INTEGER — wrapped as CHOICE to parse a bare INTEGER via AsnConvert
// @AsnType({ type: AsnTypeTypes.Choice })
// class QcRetentionPeriodAsn {
//   @AsnProp({ type: AsnPropTypes.Integer })
//   value = 0;
// }

// // PdsLocation ::= SEQUENCE { url IA5String, language PrintableString }
// class PdsLocation {
//   @AsnProp({ type: AsnPropTypes.IA5String })
//   url = '';

//   @AsnProp({ type: AsnPropTypes.PrintableString })
//   language = '';
// }

// // QcPDS ::= SEQUENCE OF PdsLocation
// @AsnType({ type: AsnTypeTypes.Sequence, itemType: PdsLocation })
// class QcPdsAsn extends AsnArray<PdsLocation> {
//   constructor(items?: PdsLocation[]) {
//     super(items);
//     Object.setPrototypeOf(this, QcPdsAsn.prototype);
//   }
// }

// // QcType ::= SEQUENCE { qcType SEQUENCE SIZE (1..MAX) OF OID }
// @AsnType({ type: AsnTypeTypes.Sequence, itemType: AsnPropTypes.ObjectIdentifier })
// class QcTypeOids extends AsnArray<string> {
//   constructor(items?: string[]) {
//     super(items);
//     Object.setPrototypeOf(this, QcTypeOids.prototype);
//   }
// }

// class QcTypeAsn {
//   @AsnProp({ type: QcTypeOids })
//   qcType = new QcTypeOids();
// }

// // QcCClegislation ::= SEQUENCE SIZE (1..MAX) OF PrintableString (SIZE 2)
// @AsnType({ type: AsnTypeTypes.Sequence, itemType: AsnPropTypes.PrintableString })
// class QcCClegislationAsn extends AsnArray<string> {
//   constructor(items?: string[]) {
//     super(items);
//     Object.setPrototypeOf(this, QcCClegislationAsn.prototype);
//   }
// }

// PSD2QcType ::= SEQUENCE { rolesOfPSP RolesOfPSP, nCAName UTF8String, nCAId UTF8String }
class RoleOfPSP {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  roleOfPspOid = '';

  @AsnProp({ type: AsnPropTypes.Utf8String })
  roleOfPspName = '';
}

@AsnType({ type: AsnTypeTypes.Sequence, itemType: RoleOfPSP })
class RolesOfPSP extends AsnArray<RoleOfPSP> {
  constructor(items?: RoleOfPSP[]) {
    super(items);
    Object.setPrototypeOf(this, RolesOfPSP.prototype);
  }
}

class QcEuPSD2 {
  @AsnProp({ type: RolesOfPSP })
  rolesOfPSP = new RolesOfPSP();

  @AsnProp({ type: AsnPropTypes.Utf8String })
  nCAName = '';

  @AsnProp({ type: AsnPropTypes.Utf8String })
  nCAId = '';
}

// ── Public data types ─────────────────────────────────────────────────────────

export interface QcLimitValueData {
  /** ISO 4217 alphabetic code (e.g. "EUR") or "ISO-4217 #978" for numeric */
  currency: string;
  amount: number;
  exponent: number;
}

export interface PdsLocationData {
  url: string;
  language: string;
}

export interface QcPsd2Data {
  roles: Array<{ oid: string; name: string }>;
  nCAName: string;
  nCAId: string;
}

export interface QcSyntaxData {
  semanticsId?: string;
  semanticsLabel?: string;
}

// ── QcStatementsExtension ─────────────────────────────────────────────────────

export class QcStatementsExtension extends Extension {
  static NAME = 'QC Statements';

  /** True when the certificate contains the id-etsi-qcs-QcCompliance statement */
  compliance!: boolean;
  /** True when the certificate contains the id-etsi-qcs-QcSSCD statement */
  sscd!: boolean;
  limitValue!: QcLimitValueData | undefined;
  retentionPeriod!: number | undefined;
  pds!: PdsLocationData[] | undefined;
  /** Resolved OID strings for each QcType identifier */
  qcTypes!: string[] | undefined;
  ccLegislation!: string[] | undefined;
  psd2!: QcPsd2Data | undefined;
  syntaxV1!: QcSyntaxData | undefined;
  syntaxV2!: QcSyntaxData | undefined;

  constructor(raw: BufferSource) {
    super(raw);
  }

  protected onInit(asn: AsnX509Extension): void {
    super.onInit(asn);

    // Initialise all typed properties to their absent state
    this.compliance      = false;
    this.sscd            = false;
    this.limitValue      = undefined;
    this.retentionPeriod = undefined;
    this.pds             = undefined;
    this.qcTypes         = undefined;
    this.ccLegislation   = undefined;
    this.psd2            = undefined;
    this.syntaxV1        = undefined;
    this.syntaxV2        = undefined;

    const statements = AsnConvert.parse(asn.extnValue, QCStatements);

    for (const stmt of statements) {
      try {
        switch (stmt.statementId) {

          case id_etsi_qcs_qcCompliance:
            this.compliance = true;
            break;

          case id_etsi_qcs_qcSSCD:
            this.sscd = true;
            break;

          case id_etsi_qcs_qcLimitValue:
            if (stmt.statementInfo) {
              const mv = AsnConvert.parse(stmt.statementInfo, MonetaryValue);
              this.limitValue = {
                currency: mv.currency.alphabetic ?? /*mv.currency.alphabeticUtf8 ??*/ `ISO-4217 #${mv.currency.numeric}`,
                amount:   mv.amount,
                exponent: mv.exponent,
              };
            }
            break;

          case id_etsi_qcs_qcRetentionPeriod:
            if (stmt.statementInfo) {
              const rp = AsnConvert.parse(stmt.statementInfo, QcEuRetentionPeriod);
              this.retentionPeriod = rp.value;
            }
            break;

          case id_etsi_qcs_qcPDS:
            if (stmt.statementInfo) {
              const pdsArr = AsnConvert.parse(stmt.statementInfo, QcEuPDS);
              this.pds = pdsArr.map(loc => ({ url: loc.url, language: loc.language }));
            }
            break;

          case id_etsi_qcs_qcType:
            if (stmt.statementInfo) {
              const qt = AsnConvert.parse(stmt.statementInfo, QcType);
              this.qcTypes = Array.from(qt/*.qcType*/);
            }
            break;

          case id_etsi_qcs_qcCClegislation:
            if (stmt.statementInfo) {
              const cc = AsnConvert.parse(stmt.statementInfo, QcCClegislation);
              this.ccLegislation = Array.from(cc);
            }
            break;

          case id_etsi_psd2:
            if (stmt.statementInfo) {
              const psd2 = AsnConvert.parse(stmt.statementInfo, QcEuPSD2);
              this.psd2 = {
                roles:   psd2.rolesOfPSP.map(r => ({
                  oid:  r.roleOfPspOid,
                  name: PSD2_ROLE_NAMES[r.roleOfPspOid] ?? r.roleOfPspName,
                })),
                nCAName: psd2.nCAName,
                nCAId:   psd2.nCAId,
              };
            }
            break;

          case id_qcs_pkixQCSyntax_v1:
          case id_qcs_pkixQCSyntax_v2: {
            const data: QcSyntaxData = {};
            if (stmt.statementInfo) {
              const si = AsnConvert.parse(stmt.statementInfo, SemanticsInformation);
              if (si.semanticsIdentifier) {
                data.semanticsId    = si.semanticsIdentifier;
                data.semanticsLabel = QC_SEMANTICS_NAMES[si.semanticsIdentifier] ?? si.semanticsIdentifier;
              }
            }
            if (stmt.statementId === id_qcs_pkixQCSyntax_v1) {
              this.syntaxV1 = data;
            } else {
              this.syntaxV2 = data;
            }
            break;
          }
        }
      } catch {
        // Skip individual statement parse errors; unrecognised or malformed
        // statements simply remain absent from the typed properties.
      }
    }
  }

  /** Returns one display line per present QC statement, in a stable order. */
  toTextLines(): string[] {
    const lines: string[] = [];

    if (this.compliance) {
      lines.push('\u2022 QcCompliance: Certificate conforms to EU eIDAS Regulation');
    }
    if (this.limitValue) {
      const v     = this.limitValue;
      const value = v.amount * Math.pow(10, v.exponent);
      lines.push(`\u2022 QcLimitValue: ${value.toLocaleString()} ${v.currency}`);
    }
    if (this.retentionPeriod !== undefined) {
      lines.push(`\u2022 QcRetentionPeriod: ${this.retentionPeriod} year(s)`);
    }
    if (this.sscd) {
      lines.push('\u2022 QcSSCD: Private key stored on SSCD/QSCD');
    }
    if (this.pds) {
      const locs = this.pds.map(l => `  [${l.language.toUpperCase()}] ${l.url}`).join('\n');
      lines.push(`\u2022 QcPDS:\n${locs}`);
    }
    if (this.qcTypes) {
      const types = this.qcTypes.map(oid => QC_TYPE_NAMES[oid] ?? oid).join(', ');
      lines.push(`\u2022 QcType: ${types}`);
    }
    if (this.ccLegislation) {
      lines.push(`\u2022 QcCClegislation: ${this.ccLegislation.join(', ')}`);
    }
    if (this.psd2) {
      const roleLines = this.psd2.roles.map(r => `    \u2022 ${r.name}`).join('\n');
      lines.push(`\u2022 PSD2 QcStatement:\n${roleLines}\n  NCA: ${this.psd2.nCAName} (${this.psd2.nCAId})`);
    }
    if (this.syntaxV1 !== undefined) {
      const label = this.syntaxV1.semanticsLabel ?? this.syntaxV1.semanticsId ?? '';
      lines.push(`\u2022 QcSyntax-v1${label ? ': ' + label : ''}`);
    }
    if (this.syntaxV2 !== undefined) {
      const label = this.syntaxV2.semanticsLabel ?? this.syntaxV2.semanticsId ?? '';
      lines.push(`\u2022 QcSyntax-v2${label ? ': ' + label : ''}`);
    }

    return lines;
  }
}

ExtensionFactory.register(id_pe_qcStatements, QcStatementsExtension);

// ── Backward-compatible helper ────────────────────────────────────────────────
// Kept for code that calls parseQcStatements(ext.rawData) directly (e.g. tests).
// In production, prefer constructing QcStatementsExtension(raw) directly.

export function parseQcStatements(rawData: ArrayBuffer | Uint8Array): string {
  const buf = rawData instanceof Uint8Array ? rawData : new Uint8Array(rawData);

  // Quick structural validation (matches the error messages expected by tests)
  const ext = derTLV(buf, 0);
  if (ext.tag !== 0x30) return '(invalid extension)';
  let off = 0;
  off = derTLV(ext.val, off).end;                             // skip extnID OID
  if (ext.val[off] === 0x01) off = derTLV(ext.val, off).end; // skip critical BOOLEAN
  const extnValue = derTLV(ext.val, off);                     // must be OCTET STRING
  if (extnValue.tag !== 0x04) return '(expected OCTET STRING)';

  try {
    // buf.slice() returns Uint8Array<ArrayBuffer> — a valid, contiguous BufferSource
    const qcExt = new QcStatementsExtension(buf.slice());
    const lines = qcExt.toTextLines();
    return lines.length > 0 ? lines.join('\n') : '(empty)';
  } catch {
    return '(parse error)';
  }
}
