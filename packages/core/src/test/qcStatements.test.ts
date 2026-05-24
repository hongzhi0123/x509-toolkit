import { parseQcStatements } from '../parsers/qcStatements';

// ---------------------------------------------------------------------------
// Helpers to build minimal DER-encoded structures for testing
// ---------------------------------------------------------------------------

/** Encode a value as a DER TLV (tag-length-value). */
function tlv(tag: number, ...values: Uint8Array[]): Uint8Array {
  const content = concat(...values);
  const lenBytes = encodeLength(content.length);
  return concat(new Uint8Array([tag]), lenBytes, content);
}

function encodeLength(len: number): Uint8Array {
  if (len < 0x80) return new Uint8Array([len]);
  if (len < 0x100) return new Uint8Array([0x81, len]);
  return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// Pre-encoded OIDs (value bytes only, without the 0x06 tag and length)
const OID_QC_STATEMENTS    = new Uint8Array([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03]);
const OID_QC_COMPLIANCE    = new Uint8Array([0x04, 0x00, 0x8e, 0x46, 0x01, 0x01]); // 0.4.0.1862.1.1
const OID_QC_SSCD          = new Uint8Array([0x04, 0x00, 0x8e, 0x46, 0x01, 0x04]); // 0.4.0.1862.1.4
const OID_QC_RETENTION     = new Uint8Array([0x04, 0x00, 0x8e, 0x46, 0x01, 0x03]); // 0.4.0.1862.1.3

/** Build the full extension SEQUENCE that parseQcStatements expects:
 *  SEQUENCE {
 *    OID(1.3.6.1.5.5.7.1.3),
 *    OCTET STRING { <qcStatementsContent> }
 *  }
 */
function buildExtension(qcStatementsContent: Uint8Array): Uint8Array {
  const oidTlv         = tlv(0x06, OID_QC_STATEMENTS);
  const octetStringTlv = tlv(0x04, qcStatementsContent);
  return tlv(0x30, oidTlv, octetStringTlv);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('parseQcStatements — error handling', () => {
  it('returns "(invalid extension)" when the outer tag is not SEQUENCE', () => {
    const buf = new Uint8Array([0x02, 0x01, 0x00]); // INTEGER, not SEQUENCE
    expect(parseQcStatements(buf)).toBe('(invalid extension)');
  });

  it('returns "(expected OCTET STRING)" when the extension value is not an OCTET STRING', () => {
    // SEQUENCE { OID, NULL } — NULL instead of OCTET STRING
    const oidTlv = tlv(0x06, OID_QC_STATEMENTS);
    const nullTlv = new Uint8Array([0x05, 0x00]);
    const ext = tlv(0x30, oidTlv, nullTlv);
    expect(parseQcStatements(ext)).toBe('(expected OCTET STRING)');
  });

  it('accepts an ArrayBuffer as input', () => {
    const inner   = tlv(0x30, tlv(0x30, tlv(0x06, OID_QC_COMPLIANCE)));
    const ext     = buildExtension(inner);
    const result  = parseQcStatements(ext.buffer as ArrayBuffer);
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });
});

describe('parseQcStatements — QcCompliance (0.4.0.1862.1.1)', () => {
  it('parses a QcCompliance statement with no additional content', () => {
    // QCStatements SEQUENCE OF: one statement SEQUENCE { OID }
    const stmt   = tlv(0x30, tlv(0x06, OID_QC_COMPLIANCE));
    const inner  = tlv(0x30, stmt);  // SEQUENCE OF QCStatement
    const ext    = buildExtension(inner);

    const result = parseQcStatements(ext);
    expect(result).toContain('QcCompliance');
    expect(result).toContain('eIDAS');
  });
});

describe('parseQcStatements — QcSSCD (0.4.0.1862.1.4)', () => {
  it('parses a QcSSCD statement', () => {
    const stmt  = tlv(0x30, tlv(0x06, OID_QC_SSCD));
    const inner = tlv(0x30, stmt);
    const ext   = buildExtension(inner);

    const result = parseQcStatements(ext);
    expect(result).toContain('QcSSCD');
    expect(result).toContain('SSCD');
  });
});

describe('parseQcStatements — QcRetentionPeriod (0.4.0.1862.1.3)', () => {
  it('parses the retention period in years', () => {
    // QcRetentionPeriod info is an INTEGER directly (no outer SEQUENCE wrapper).
    // stmt: SEQUENCE { OID, INTEGER(10) }
    const intTlv    = tlv(0x02, new Uint8Array([0x0a])); // INTEGER 10
    const stmt      = tlv(0x30, tlv(0x06, OID_QC_RETENTION), intTlv);
    const inner     = tlv(0x30, stmt);
    const ext       = buildExtension(inner);

    const result = parseQcStatements(ext);
    expect(result).toContain('QcRetentionPeriod');
    expect(result).toContain('10');
  });
});

describe('parseQcStatements — multiple statements', () => {
  it('returns one line per statement', () => {
    const stmtCompliance = tlv(0x30, tlv(0x06, OID_QC_COMPLIANCE));
    const stmtSscd       = tlv(0x30, tlv(0x06, OID_QC_SSCD));
    const inner = tlv(0x30, stmtCompliance, stmtSscd);
    const ext   = buildExtension(inner);

    const result = parseQcStatements(ext);
    const lines  = result.split('\n');
    expect(lines.length).toBe(2);
    expect(result).toContain('QcCompliance');
    expect(result).toContain('QcSSCD');
  });

  it('returns "(empty)" for a SEQUENCE with no statements', () => {
    const inner = tlv(0x30); // empty SEQUENCE OF
    const ext   = buildExtension(inner);
    expect(parseQcStatements(ext)).toBe('(empty)');
  });
});
