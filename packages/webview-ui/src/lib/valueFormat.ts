export type ValueMode = 'hex' | 'dec' | 'b64';

const HEX_RE = /^[0-9a-fA-F]+$/;

export function normalizeHex(value: string): string {
  return value.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
}

export function toColonHex(value: string): string | undefined {
  const hex = normalizeHex(value);
  if (!hex || hex.length % 2 !== 0) return undefined;
  const bytes = hex.match(/.{2}/g);
  return bytes ? bytes.join(':') : undefined;
}

export function hexToDecimal(value: string): string | undefined {
  const hex = normalizeHex(value);
  if (!hex || !HEX_RE.test(hex)) return undefined;
  try {
    return BigInt(`0x${hex}`).toString(10);
  } catch {
    return undefined;
  }
}

export function hexToBase64(value: string): string | undefined {
  const hex = normalizeHex(value);
  if (!hex || hex.length % 2 !== 0) return undefined;
  try {
    let binary = '';
    for (let i = 0; i < hex.length; i += 2) {
      binary += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    }
    return btoa(binary);
  } catch {
    return undefined;
  }
}

export function formatHexValue(value: string, mode: ValueMode): string | undefined {
  if (mode === 'hex') return toColonHex(value);
  if (mode === 'dec') return hexToDecimal(value);
  return hexToBase64(value);
}

export function getAvailableFormats(value: string): ValueMode[] {
  const available: ValueMode[] = [];
  if (formatHexValue(value, 'hex')) available.push('hex');
  if (formatHexValue(value, 'dec')) available.push('dec');
  if (formatHexValue(value, 'b64')) available.push('b64');
  return available;
}

export function nextValueMode(current: ValueMode, available: ValueMode[]): ValueMode {
  if (available.length === 0) return 'hex';
  const idx = available.indexOf(current);
  if (idx < 0) return available[0];
  return available[(idx + 1) % available.length];
}

export function modeBadgeText(mode: ValueMode): string {
  if (mode === 'hex') return '16';
  if (mode === 'dec') return '10';
  return '64';
}
