import * as crypto from 'crypto';
import { parseKeyFile, isEncryptedKey, looksLikeKeyFile, generateKeyPair } from '../parsers/keyParser';

// ──────────────────────────────────────────────────────────────────────────────
// Key material generated once for the whole suite
// ──────────────────────────────────────────────────────────────────────────────

let rsaPrivKeyPem: string;
let rsaPubKeyPem: string;
let rsaDerBuf: Buffer;
let encryptedRsaPrivKeyPem: string;
let ecPrivKeyPem: string;

const PASSPHRASE = 'test-key-passphrase';

beforeAll(() => {
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  rsaPrivKeyPem = rsa.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  rsaPubKeyPem  = rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string;
  rsaDerBuf     = rsa.privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  encryptedRsaPrivKeyPem = rsa.privateKey.export({
    type: 'pkcs8', format: 'pem',
    cipher: 'aes-256-cbc', passphrase: PASSPHRASE,
  }) as string;

  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  ecPrivKeyPem = ec.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}, 30_000);

// ──────────────────────────────────────────────────────────────────────────────
// parseKeyFile — RSA private key (PEM / PKCS#8)
// ──────────────────────────────────────────────────────────────────────────────

describe('parseKeyFile — RSA private key (PEM)', () => {
  it('returns StandaloneKeyData without throwing', () => {
    expect(() => parseKeyFile(Buffer.from(rsaPrivKeyPem))).not.toThrow();
  });

  it('reports algorithm as RSA', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.algorithm).toBe('RSA');
  });

  it('reports kind as private', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.kind).toBe('private');
  });

  it('reports key size as 2048', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.keySize).toBe(2048);
  });

  it('includes a SPKI PEM', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.spkiPem).toContain('-----BEGIN PUBLIC KEY-----');
    expect(data.spkiPem).toContain('-----END PUBLIC KEY-----');
  });

  it('includes a PKCS#8 PEM for the private key', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.pkcs8Pem).toContain('-----BEGIN PRIVATE KEY-----');
  });

  it('sets isEncrypted to false', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.isEncrypted).toBe(false);
  });

  it('includes a non-empty key ID (colon-hex SHA-1 of SPKI DER)', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.keyId).toMatch(/^[0-9a-f:]+$/);
    expect(data.keyId.length).toBeGreaterThan(0);
  });

  it('includes RSA modulus and public exponent', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(data.modulus).toBeTruthy();
    expect(data.publicExponent).toBeTruthy();
  });

  it('returns the underlying Node.js KeyObject', () => {
    const { nodeKey } = parseKeyFile(Buffer.from(rsaPrivKeyPem));
    expect(nodeKey).toBeDefined();
    expect(nodeKey.asymmetricKeyType).toBe('rsa');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseKeyFile — EC private key (PEM / PKCS#8)
// ──────────────────────────────────────────────────────────────────────────────

describe('parseKeyFile — EC private key (PEM)', () => {
  it('reports algorithm as EC', () => {
    const { data } = parseKeyFile(Buffer.from(ecPrivKeyPem));
    expect(data.algorithm).toBe('EC');
  });

  it('reports named curve as P-256', () => {
    const { data } = parseKeyFile(Buffer.from(ecPrivKeyPem));
    expect(data.namedCurve).toBe('P-256');
  });

  it('reports kind as private', () => {
    const { data } = parseKeyFile(Buffer.from(ecPrivKeyPem));
    expect(data.kind).toBe('private');
  });

  it('includes a SPKI PEM', () => {
    const { data } = parseKeyFile(Buffer.from(ecPrivKeyPem));
    expect(data.spkiPem).toContain('-----BEGIN PUBLIC KEY-----');
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseKeyFile — public key (SPKI PEM)
// ──────────────────────────────────────────────────────────────────────────────

describe('parseKeyFile — public key (SPKI PEM)', () => {
  it('reports kind as public', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPubKeyPem));
    expect(data.kind).toBe('public');
  });

  it('does not include pkcs8Pem', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPubKeyPem));
    expect(data.pkcs8Pem).toBeUndefined();
  });

  it('includes a SPKI PEM identical to the input', () => {
    const { data } = parseKeyFile(Buffer.from(rsaPubKeyPem));
    expect(data.spkiPem.trim()).toBe(rsaPubKeyPem.trim());
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseKeyFile — encrypted private key
// ──────────────────────────────────────────────────────────────────────────────

describe('parseKeyFile — encrypted private key', () => {
  it('throws with "passphrase" in the message when no passphrase is provided', () => {
    expect(() => parseKeyFile(Buffer.from(encryptedRsaPrivKeyPem))).toThrow(/passphrase/i);
  });

  it('succeeds when the correct passphrase is provided', () => {
    const { data } = parseKeyFile(Buffer.from(encryptedRsaPrivKeyPem), PASSPHRASE);
    expect(data.kind).toBe('private');
    expect(data.algorithm).toBe('RSA');
  });

  it('throws when an incorrect passphrase is provided', () => {
    expect(() => parseKeyFile(Buffer.from(encryptedRsaPrivKeyPem), 'wrong-passphrase')).toThrow();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseKeyFile — DER binary input (PKCS#8)
// ──────────────────────────────────────────────────────────────────────────────

describe('parseKeyFile — DER binary input', () => {
  it('parses a PKCS#8 DER private key', () => {
    const { data } = parseKeyFile(rsaDerBuf);
    expect(data.kind).toBe('private');
    expect(data.algorithm).toBe('RSA');
    expect(data.keySize).toBe(2048);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// parseKeyFile — error handling
// ──────────────────────────────────────────────────────────────────────────────

describe('parseKeyFile — error handling', () => {
  it('throws for completely invalid input', () => {
    expect(() => parseKeyFile(Buffer.from('not a key at all'))).toThrow();
  });

  it('throws for an empty buffer', () => {
    expect(() => parseKeyFile(Buffer.alloc(0))).toThrow();
  });

  it('throws for a certificate PEM (not a key)', () => {
    const certPem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
    expect(() => parseKeyFile(Buffer.from(certPem))).toThrow();
  });

  it('throws for malformed DER public key input', () => {
    const malformedDer = Buffer.from('3006020101020101', 'hex');
    expect(() => parseKeyFile(malformedDer)).toThrow(/not a recognised private or public key format/i);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// isEncryptedKey
// ──────────────────────────────────────────────────────────────────────────────

describe('isEncryptedKey', () => {
  it('returns false for an unencrypted PKCS#8 PEM key', () => {
    expect(isEncryptedKey(Buffer.from(rsaPrivKeyPem))).toBe(false);
  });

  it('returns true for an encrypted PKCS#8 PEM key', () => {
    expect(isEncryptedKey(Buffer.from(encryptedRsaPrivKeyPem))).toBe(true);
  });

  it('returns false for a public key PEM', () => {
    expect(isEncryptedKey(Buffer.from(rsaPubKeyPem))).toBe(false);
  });

  it('returns false for non-key content', () => {
    expect(isEncryptedKey(Buffer.from('not a key'))).toBe(false);
  });

  it('returns false for empty buffer', () => {
    expect(isEncryptedKey(Buffer.alloc(0))).toBe(false);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// looksLikeKeyFile
// ──────────────────────────────────────────────────────────────────────────────

describe('looksLikeKeyFile', () => {
  it('returns true for a PKCS#8 unencrypted private key PEM', () => {
    expect(looksLikeKeyFile(Buffer.from(rsaPrivKeyPem))).toBe(true);
  });

  it('returns true for an encrypted PKCS#8 private key PEM', () => {
    expect(looksLikeKeyFile(Buffer.from(encryptedRsaPrivKeyPem))).toBe(true);
  });

  it('returns true for a SPKI public key PEM', () => {
    expect(looksLikeKeyFile(Buffer.from(rsaPubKeyPem))).toBe(true);
  });

  it('returns false for a certificate PEM', () => {
    const certPem = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
    expect(looksLikeKeyFile(Buffer.from(certPem))).toBe(false);
  });

  it('returns false for a CSR PEM', () => {
    const csrPem = '-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----';
    expect(looksLikeKeyFile(Buffer.from(csrPem))).toBe(false);
  });

  it('returns false for random text', () => {
    expect(looksLikeKeyFile(Buffer.from('hello world'))).toBe(false);
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// generateKeyPair
// ──────────────────────────────────────────────────────────────────────────────

describe('generateKeyPair', () => {
  it('generates an EC P-256 key pair', async () => {
    const { data, privateKeyPem, publicKeyPem } = await generateKeyPair('EC-P256');
    expect(data.algorithm).toBe('EC');
    expect(data.namedCurve).toBe('P-256');
    expect(privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
    expect(publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
  }, 10_000);

  it('generates an EC P-384 key pair', async () => {
    const { data } = await generateKeyPair('EC-P384');
    expect(data.algorithm).toBe('EC');
    expect(data.namedCurve).toBe('P-384');
  }, 10_000);

  it('generates an RSA-2048 key pair', async () => {
    const { data, privateKeyPem, publicKeyPem } = await generateKeyPair('RSA-2048');
    expect(data.algorithm).toBe('RSA');
    expect(data.keySize).toBe(2048);
    expect(privateKeyPem).toContain('-----BEGIN PRIVATE KEY-----');
    expect(publicKeyPem).toContain('-----BEGIN PUBLIC KEY-----');
  }, 30_000);

  it('generated private key can be re-parsed by parseKeyFile', async () => {
    const { privateKeyPem } = await generateKeyPair('EC-P256');
    const { data } = parseKeyFile(Buffer.from(privateKeyPem));
    expect(data.algorithm).toBe('EC');
    expect(data.namedCurve).toBe('P-256');
  }, 10_000);
});

// ──────────────────────────────────────────────────────────────────────────────
// generateKeyPair — error handling
// ──────────────────────────────────────────────────────────────────────────────

describe('generateKeyPair — error handling', () => {
  it('rejects unsupported algorithms', async () => {
    await expect(generateKeyPair('RSA-1024' as never)).rejects.toThrow(/unsupported key algorithm/i);
  });
});
