import { AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, AsnArray } from '@peculiar/asn1-schema';
import { id_etsi_qct_eseal, id_etsi_qct_esign, id_etsi_qct_web } from "@peculiar/asn1-x509-qualified-etsi";

// ── OID constants ─────────────────────────────────────────────────────────────
export const id_etsi_psd2                = '0.4.0.19495.2';

// ── Name lookup tables ────────────────────────────────────────────────────────
export const PSD2_ROLE_NAMES: Record<string, string> = {
  '0.4.0.19495.1.1': 'PSP_AS (Account Servicing)',
  '0.4.0.19495.1.2': 'PSP_PI (Payment Initiation)',
  '0.4.0.19495.1.3': 'PSP_AI (Account Information)',
  '0.4.0.19495.1.4': 'PSP_IC (Card-Based Payment Instruments)',
};

export const QC_TYPE_NAMES: Record<string, string> = {
  [id_etsi_qct_esign]: 'Electronic Signature (eSign)',
  [id_etsi_qct_eseal]: 'Electronic Seal (eSeal)',
  [id_etsi_qct_web]: 'Website Authentication (Web)',
};

export const QC_SEMANTICS_NAMES: Record<string, string> = {
  '0.4.0.1862.1.1.1': 'Natural Person',
  '0.4.0.1862.1.1.2': 'Legal Person',
};

// ── ASN.1 structure definitions (ETSI EN 319 412-5 / ETSI TS 119 495) ─────────

// PSD2QcType ::= SEQUENCE { rolesOfPSP RolesOfPSP, nCAName UTF8String, nCAId UTF8String }
export class RoleOfPSP {
  @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
  roleOfPspOid = '';

  @AsnProp({ type: AsnPropTypes.Utf8String })
  roleOfPspName = '';
}

@AsnType({ type: AsnTypeTypes.Sequence, itemType: RoleOfPSP })
export class RolesOfPSP extends AsnArray<RoleOfPSP> {
  constructor(items?: RoleOfPSP[]) {
    super(items);
    Object.setPrototypeOf(this, RolesOfPSP.prototype);
  }
}

export class QcEuPSD2 {
  @AsnProp({ type: RolesOfPSP })
  rolesOfPSP = new RolesOfPSP();

  @AsnProp({ type: AsnPropTypes.Utf8String })
  nCAName = '';

  @AsnProp({ type: AsnPropTypes.Utf8String })
  nCAId = '';
}
