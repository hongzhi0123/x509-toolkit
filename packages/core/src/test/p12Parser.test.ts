import { parseP12, createSelfSignedP12 } from '../parsers/p12Parser';

// RSA-2048 key generation is slow; allow up to 60 s for the whole suite.
jest.setTimeout(60_000);

// ---------------------------------------------------------------------------
// Shared P12 generated once for all tests
// ---------------------------------------------------------------------------

let p12Buffer: Buffer;

beforeAll(async () => {
  p12Buffer = await createSelfSignedP12('P12 Test', 365, 'test-password');
});

// ---------------------------------------------------------------------------
// createSelfSignedP12
// ---------------------------------------------------------------------------

describe('createSelfSignedP12', () => {
  it('returns a non-empty Buffer', () => {
    expect(Buffer.isBuffer(p12Buffer)).toBe(true);
    expect(p12Buffer.length).toBeGreaterThan(0);
  });

  it('begins with the PKCS#12 PFX ASN.1 SEQUENCE tag (0x30)', () => {
    // A valid DER-encoded P12 always starts with 0x30 (SEQUENCE)
    expect(p12Buffer[0]).toBe(0x30);
  });

  it('generates different P12 files on successive calls (random serial)', async () => {
    const second = await createSelfSignedP12('P12 Test', 365, 'test-password');
    // The buffers will differ because of a random 128-bit serial number
    expect(p12Buffer.equals(second)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// parseP12
// ---------------------------------------------------------------------------

describe('parseP12', () => {
  it('extracts exactly one certificate', async () => {
    const certs = await parseP12(p12Buffer, 'test-password');
    expect(certs).toHaveLength(1);
  });

  it('populates the correct CN in the extracted certificate', async () => {
    const [cert] = await parseP12(p12Buffer, 'test-password');
    expect(cert.subject.commonName).toBe('P12 Test');
  });

  it('marks the extracted certificate as non-CA (cA: false in basicConstraints)', async () => {
    // createSelfSignedP12 explicitly sets basicConstraints cA: false
    const [cert] = await parseP12(p12Buffer, 'test-password');
    expect(cert.isCA).toBe(false);
  });

  it('marks the certificate as self-signed', async () => {
    const [cert] = await parseP12(p12Buffer, 'test-password');
    expect(cert.isSelfSigned).toBe(true);
  });

  it('attaches the private key to the certificate', async () => {
    const [cert] = await parseP12(p12Buffer, 'test-password');
    expect(cert.privateKey).toBeDefined();
    expect(cert.privateKey?.algorithm).toBeTruthy();
  });

  it('throws an error for an incorrect password', async () => {
    await expect(parseP12(p12Buffer, 'wrong-password')).rejects.toThrow(
      /incorrect password|corrupted/i,
    );
  });

  it('throws an error for an empty buffer', async () => {
    await expect(parseP12(Buffer.alloc(0), 'any')).rejects.toThrow();
  });

  it('throws an error for garbage input', async () => {
    const garbage = Buffer.from('this is not a p12 file');
    await expect(parseP12(garbage, 'any')).rejects.toThrow();
  });
});
