export type PemOutputMode = 'wrapped' | 'single-line' | 'base64';

export interface PemFormatOptions {
  mode?: PemOutputMode;
  lineWidth?: number;
}

const PEM_BLOCK_RE = /-----BEGIN ([^-\r\n]+)-----([\s\S]*?)-----END \1-----/g;
const BASE64_RE = /^[A-Za-z0-9+/=]+$/;

function hasPemMarkers(text: string): boolean {
  return text.includes('-----BEGIN ') && text.includes('-----END ');
}

function wrapBase64(base64: string, lineWidth: number): string {
  const chunks = base64.match(new RegExp(`.{1,${lineWidth}}`, 'g'));
  return chunks ? chunks.join('\n') : '';
}

function normalisePemBody(body: string): string {
  const base64 = body.replace(/\s+/g, '');
  if (!base64) {
    throw new Error('PEM body is empty.');
  }
  if (!BASE64_RE.test(base64)) {
    throw new Error('PEM body is not valid base64.');
  }
  return base64;
}

function transformPemBlocks(input: string, options: PemFormatOptions = {}): string {
  if (!hasPemMarkers(input)) {
    return input;
  }

  const mode = options.mode ?? 'wrapped';
  const lineWidth = options.lineWidth ?? 64;
  if (!Number.isFinite(lineWidth) || lineWidth <= 0) {
    throw new Error('lineWidth must be a positive number.');
  }

  let found = false;
  const transformed = input.replace(PEM_BLOCK_RE, (_match, label: string, body: string) => {
    found = true;
    const base64 = normalisePemBody(body);
    if (mode === 'base64') {
      return base64;
    }
    if (mode === 'single-line') {
      return `-----BEGIN ${label}-----${base64}-----END ${label}-----`;
    }
    return `-----BEGIN ${label}-----\n${wrapBase64(base64, lineWidth)}\n-----END ${label}-----`;
  });

  if (!found) {
    return input;
  }

  return transformed;
}

export function containsPemBlock(input: string): boolean {
  PEM_BLOCK_RE.lastIndex = 0;
  return PEM_BLOCK_RE.test(input);
}

export function canonicalizePemBlocks(input: string, lineWidth = 64): string {
  return transformPemBlocks(input, { mode: 'wrapped', lineWidth });
}

export function toOneLinePem(input: string): string {
  return transformPemBlocks(input, { mode: 'single-line' });
}

export function toRawBase64(input: string): string {
  return transformPemBlocks(input, { mode: 'base64' });
}
