import { derTLV, derOid, derInt, derStr } from '../utils/derUtils';

describe('derTLV', () => {
  it('parses a simple TLV at offset 0', () => {
    // SEQUENCE (0x30), length 3, value [0x01, 0x02, 0x03]
    const buf = new Uint8Array([0x30, 0x03, 0x01, 0x02, 0x03]);
    const r = derTLV(buf, 0);
    expect(r.tag).toBe(0x30);
    expect(r.val).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
    expect(r.end).toBe(5);
  });

  it('parses a TLV at a non-zero offset', () => {
    // Padding byte 0xff, then INTEGER (0x02), length 1, value 0x2a
    const buf = new Uint8Array([0xff, 0x02, 0x01, 0x2a]);
    const r = derTLV(buf, 1);
    expect(r.tag).toBe(0x02);
    expect(r.val).toEqual(new Uint8Array([0x2a]));
    expect(r.end).toBe(4);
  });

  it('parses a TLV with long-form (two-byte) length', () => {
    // OCTET STRING (0x04), long-form length 0x81 0x80 = 128, then 128 bytes of 0xAA
    const content = new Uint8Array(128).fill(0xaa);
    const buf = new Uint8Array([0x04, 0x81, 0x80, ...content]);
    const r = derTLV(buf, 0);
    expect(r.tag).toBe(0x04);
    expect(r.val.length).toBe(128);
    expect(r.val[0]).toBe(0xaa);
    expect(r.end).toBe(131);
  });

  it('parses zero-length value', () => {
    const buf = new Uint8Array([0x05, 0x00]); // NULL tag, length 0
    const r = derTLV(buf, 0);
    expect(r.tag).toBe(0x05);
    expect(r.val.length).toBe(0);
    expect(r.end).toBe(2);
  });

  it('sequential parsing — end points to the next TLV', () => {
    // Two consecutive INTEGERs: 0x02 0x01 0x01  and  0x02 0x01 0x02
    const buf = new Uint8Array([0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    const first = derTLV(buf, 0);
    const second = derTLV(buf, first.end);
    expect(first.val[0]).toBe(0x01);
    expect(second.val[0]).toBe(0x02);
  });
});

describe('derOid', () => {
  it('returns an empty string for empty input', () => {
    expect(derOid(new Uint8Array([]))).toBe('');
  });

  it('decodes 2.5.4.3 (commonName)', () => {
    // First byte encodes arcs 2 and 5: 2*40+5 = 85 = 0x55
    // Then 4 = 0x04, 3 = 0x03
    expect(derOid(new Uint8Array([0x55, 0x04, 0x03]))).toBe('2.5.4.3');
  });

  it('decodes 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)', () => {
    // 1.2 → 1*40+2 = 42 = 0x2a
    // 840  → multi-byte: [0x86, 0x48]
    // 113549 → multi-byte: [0x86, 0xf7, 0x0d]
    // 1 → 0x01, 1 → 0x01, 11 → 0x0b
    const bytes = new Uint8Array([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);
    expect(derOid(bytes)).toBe('1.2.840.113549.1.1.11');
  });

  it('decodes 0.4.0.1862.1.1 (QcCompliance)', () => {
    // 0.4 → 0*40+4 = 4 = 0x04
    // 0 → 0x00
    // 1862 → [0x8e, 0x46]
    // 1 → 0x01, 1 → 0x01
    const bytes = new Uint8Array([0x04, 0x00, 0x8e, 0x46, 0x01, 0x01]);
    expect(derOid(bytes)).toBe('0.4.0.1862.1.1');
  });

  it('decodes 1.3.6.1.5.5.7.1.1 (Authority Information Access)', () => {
    // 1.3 → 1*40+3 = 43 = 0x2b
    // 6, 1, 5, 5, 7, 1, 1 — all single bytes
    const bytes = new Uint8Array([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]);
    expect(derOid(bytes)).toBe('1.3.6.1.5.5.7.1.1');
  });
});

describe('derInt', () => {
  it('returns 0 for an empty buffer', () => {
    expect(derInt(new Uint8Array([]))).toBe(0);
  });

  it('decodes a single positive byte', () => {
    expect(derInt(new Uint8Array([42]))).toBe(42);
  });

  it('decodes zero', () => {
    expect(derInt(new Uint8Array([0x00]))).toBe(0);
  });

  it('decodes -1 when MSB of first byte is set (0xff)', () => {
    expect(derInt(new Uint8Array([0xff]))).toBe(-1);
  });

  it('decodes -128 (0x80)', () => {
    expect(derInt(new Uint8Array([0x80]))).toBe(-128);
  });

  it('decodes multi-byte value 300', () => {
    // 300 = 0x012c → [0x01, 0x2c]
    expect(derInt(new Uint8Array([0x01, 0x2c]))).toBe(300);
  });

  it('decodes 256 from [0x00, 0x01, 0x00] (DER leading-zero form)', () => {
    expect(derInt(new Uint8Array([0x00, 0x01, 0x00]))).toBe(256);
  });

  it('decodes 127 (largest single positive byte)', () => {
    expect(derInt(new Uint8Array([0x7f]))).toBe(127);
  });
});

describe('derStr', () => {
  it('returns an empty string for empty input', () => {
    expect(derStr(new Uint8Array([]))).toBe('');
  });

  it('decodes a basic ASCII string', () => {
    const bytes = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]); // "hello"
    expect(derStr(bytes)).toBe('hello');
  });

  it('decodes a single space character', () => {
    expect(derStr(new Uint8Array([0x20]))).toBe(' ');
  });

  it('decodes a UTF-8 multi-byte character', () => {
    const bytes = new Uint8Array(Buffer.from('café', 'utf8'));
    expect(derStr(bytes)).toBe('café');
  });

  it('decodes a full sentence', () => {
    const sentence = 'Hello, World!';
    const bytes = new Uint8Array(Buffer.from(sentence, 'utf8'));
    expect(derStr(bytes)).toBe(sentence);
  });
});
