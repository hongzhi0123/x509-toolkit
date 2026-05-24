// Minimal DER TLV reader used for bespoke extension parsing.

export function derTLV(buf: Uint8Array, off: number): { tag: number; val: Uint8Array; end: number } {
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

export function derOid(b: Uint8Array): string {
  if (!b.length) return '';
  const c: number[] = [Math.floor(b[0] / 40), b[0] % 40];
  let acc = 0;
  for (let i = 1; i < b.length; i++) {
    acc = (acc << 7) | (b[i] & 0x7f);
    if (!(b[i] & 0x80)) { c.push(acc); acc = 0; }
  }
  return c.join('.');
}

export function derInt(b: Uint8Array): number {
  if (!b.length) return 0;
  let v = b[0] & 0x80 ? b[0] - 256 : b[0];
  for (let i = 1; i < b.length; i++) v = v * 256 + b[i];
  return v;
}

export function derStr(b: Uint8Array): string {
  return Buffer.from(b).toString('utf8');
}
