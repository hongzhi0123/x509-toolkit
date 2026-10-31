import { canonicalizePemBlocks, containsPemBlock, toOneLinePem, toRawBase64 } from '../utils/pemUtils';

const PEM = [
  '-----BEGIN CERTIFICATE-----',
  'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=',
  '-----END CERTIFICATE-----',
].join('\n');

describe('pemUtils', () => {
  it('detects PEM blocks', () => {
    expect(containsPemBlock(PEM)).toBe(true);
    expect(containsPemBlock('plain text')).toBe(false);
  });

  it('canonicalizes one-line PEM into wrapped form', () => {
    const oneLine = PEM.replace(/\n/g, '');
    const normalized = canonicalizePemBlocks(oneLine, 64);
    expect(normalized).toContain('-----BEGIN CERTIFICATE-----\n');
    expect(normalized).toContain('\n-----END CERTIFICATE-----');
    expect(normalized).toContain('QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=');
  });

  it('keeps canonical PEM stable', () => {
    const normalized = canonicalizePemBlocks(PEM, 64);
    expect(normalized).toBe(PEM);
  });

  it('converts PEM to single-line form', () => {
    const oneLine = toOneLinePem(PEM);
    expect(oneLine).toBe(
      '-----BEGIN CERTIFICATE-----QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=-----END CERTIFICATE-----',
    );
  });

  it('extracts raw base64 from PEM', () => {
    const base64 = toRawBase64(PEM);
    expect(base64).toBe('QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=');
  });

  it('throws when PEM body contains invalid base64 characters', () => {
    const invalidPem = [
      '-----BEGIN CERTIFICATE-----',
      'INVALID*BASE64',
      '-----END CERTIFICATE-----',
    ].join('\n');
    expect(() => canonicalizePemBlocks(invalidPem)).toThrow(/base64/i);
  });

  it('supports multiple PEM blocks in one input', () => {
    const chain = `${PEM}\n${PEM}`;
    const oneLineChain = chain.replace(/\n/g, '');
    const normalized = canonicalizePemBlocks(oneLineChain, 64);
    const beginCount = (normalized.match(/-----BEGIN CERTIFICATE-----/g) ?? []).length;
    expect(beginCount).toBe(2);
  });
});
