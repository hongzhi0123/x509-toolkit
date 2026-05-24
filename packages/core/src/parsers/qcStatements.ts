// QC Statements extension — OID 1.3.6.1.5.5.7.1.3
// Follows the @peculiar/x509 Extension subclass pattern.
// Standards: ETSI EN 319 412-5, RFC 3739, ETSI TS 119 495 (PSD2)

import { AsnConvert } from '@peculiar/asn1-schema';
import { Extension as AsnX509Extension } from '@peculiar/asn1-x509';
import { Extension, ExtensionFactory, TextObject } from '@peculiar/x509';
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
  id_etsi_qcs_qcPDS,
  id_etsi_qcs_qcCClegislation,
  id_etsi_qcs_qcSSCD,
  id_etsi_qcs_qcLimitValue,
  id_etsi_qcs_qcRetentionPeriod,
  QcCClegislation,
  QcType,
  QcEuPDS,
  QcEuRetentionPeriod,
  MonetaryValue,
  QcEuLimitValue
} from '@peculiar/asn1-x509-qualified-etsi';
import { derTLV } from '../utils/derUtils'; // used only in the backward-compat shim
import { id_etsi_psd2, PSD2_ROLE_NAMES, QC_SEMANTICS_NAMES, QC_TYPE_NAMES, QcEuPSD2 } from '../types/qcEuPsd2';

// ── QcStatementsExtension ─────────────────────────────────────────────────────

export class QcStatementsExtension extends Extension {
  static NAME = 'QC Statements';

  /** True when the certificate contains the id-etsi-qcs-QcCompliance statement */
  compliance!: boolean;
  /** True when the certificate contains the id-etsi-qcs-QcSSCD statement */
  sscd!: boolean;
  limitValue!: QcEuLimitValue | undefined;
  retentionPeriod!: number | undefined;
  pds!: QcEuPDS | undefined;
  /** OID strings for each QcType identifier */
  qcTypes!: string[] | undefined;
  ccLegislation!: string[] | undefined;
  psd2!: QcEuPSD2 | undefined;
  syntaxV1!: SemanticsInformation | undefined;
  syntaxV2!: SemanticsInformation | undefined;

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
              this.limitValue = AsnConvert.parse(stmt.statementInfo, MonetaryValue);
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
              this.pds = AsnConvert.parse(stmt.statementInfo, QcEuPDS);
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
              this.psd2 = AsnConvert.parse(stmt.statementInfo, QcEuPSD2);
            }
            break;

          case id_qcs_pkixQCSyntax_v1:
          case id_qcs_pkixQCSyntax_v2: {
            const si = stmt.statementInfo
              ? AsnConvert.parse(stmt.statementInfo, SemanticsInformation)
              : new SemanticsInformation();
            if (stmt.statementId === id_qcs_pkixQCSyntax_v1) {
              this.syntaxV1 = si;
            } else {
              this.syntaxV2 = si;
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

  /** Returns a TextObject for use with the @peculiar/x509 TextConverter pipeline. */
  toTextObject(): TextObject {
    const obj = new TextObject(QcStatementsExtension.NAME);

    if (this.compliance) {
      obj['QcCompliance'] = 'Certificate conforms to EU eIDAS Regulation';
    }
    if (this.limitValue) {
      const mv       = this.limitValue;
      const currency = mv.currency.alphabetic ?? `ISO-4217 #${mv.currency.numeric}`;
      const value    = mv.amount * Math.pow(10, mv.exponent);
      obj['QcLimitValue'] = `${value.toLocaleString()} ${currency}`;
    }
    if (this.retentionPeriod !== undefined) {
      obj['QcRetentionPeriod'] = `${this.retentionPeriod} year(s)`;
    }
    if (this.sscd) {
      obj['QcSSCD'] = 'Private key stored on SSCD/QSCD';
    }
    if (this.pds) {
      obj['QcPDS'] = this.pds.map(l => `[${l.language.toUpperCase()}] ${l.url}`).join(', ');
    }
    if (this.qcTypes) {
      obj['QcType'] = this.qcTypes.map(oid => QC_TYPE_NAMES[oid] ?? oid).join(', ');
    }
    if (this.ccLegislation) {
      obj['QcCClegislation'] = this.ccLegislation.join(', ');
    }
    if (this.psd2) {
      obj['PSD2 Roles'] = this.psd2.rolesOfPSP
        .map(r => PSD2_ROLE_NAMES[r.roleOfPspOid] ?? r.roleOfPspName)
        .join(', ');
      obj['PSD2 NCA'] = `${this.psd2.nCAName} (${this.psd2.nCAId})`;
    }
    if (this.syntaxV1 !== undefined) {
      const id = this.syntaxV1.semanticsIdentifier;
      obj['QcSyntax-v1'] = id ? (QC_SEMANTICS_NAMES[id] ?? id) : '(no semantics identifier)';
    }
    if (this.syntaxV2 !== undefined) {
      const id = this.syntaxV2.semanticsIdentifier;
      obj['QcSyntax-v2'] = id ? (QC_SEMANTICS_NAMES[id] ?? id) : '(no semantics identifier)';
    }

    return obj;
  }

  /** Returns one display line per present QC statement, in a stable order. */
  toTextLines(): string[] {
    const lines: string[] = [];

    if (this.compliance) {
      lines.push('\u2022 QcCompliance: Certificate conforms to EU eIDAS Regulation');
    }
    if (this.limitValue) {
      const mv    = this.limitValue;
      const currency = mv.currency.alphabetic ?? `ISO-4217 #${mv.currency.numeric}`;
      const value = mv.amount * Math.pow(10, mv.exponent);
      lines.push(`\u2022 QcLimitValue: ${value.toLocaleString()} ${currency}`);
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
      const roleLines = this.psd2.rolesOfPSP
        .map(r => `    \u2022 ${PSD2_ROLE_NAMES[r.roleOfPspOid] ?? r.roleOfPspName}`)
        .join('\n');
      lines.push(`\u2022 PSD2 QcStatement:\n${roleLines}\n  NCA: ${this.psd2.nCAName} (${this.psd2.nCAId})`);
    }
    if (this.syntaxV1 !== undefined) {
      const id = this.syntaxV1.semanticsIdentifier;
      const label = id ? (QC_SEMANTICS_NAMES[id] ?? id) : '';
      lines.push(`\u2022 QcSyntax-v1${label ? ': ' + label : ''}`);
    }
    if (this.syntaxV2 !== undefined) {
      const id = this.syntaxV2.semanticsIdentifier;
      const label = id ? (QC_SEMANTICS_NAMES[id] ?? id) : '';
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
