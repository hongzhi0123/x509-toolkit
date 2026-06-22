import * as crypto from 'crypto';
import * as forge from 'node-forge';
import { bufToHex, hexColons } from '../utils/certUtils';
import type { StandaloneKeyData, KeyAlgorithm } from '../types/types';

const ALG_DISPLAY: Record<string, string> = {
  rsa: 'RSA', 'rsa-pss': 'RSA-PSS', ec: 'EC',
  ed25519: 'Ed25519', ed448: 'Ed448', x25519: 'X25519', x448: 'X448',
};

const CURVE_DISPLAY: Record<string, string> = {
  prime256v1: 'P-256', secp384r1: 'P-384', secp521r1: 'P-521', secp256k1: 'secp256k1',
};

type InputFormat = StandaloneKeyData['inputFormat'];

function detectPemFormat(text: string): InputFormat {
  if (/^-----BEGIN PRIVATE KEY-----/m.test(text)) return 'pkcs8-pem';
  if (/^-----BEGIN ENCRYPTED PRIVATE KEY-----/m.test(text)) return 'encrypted-pkcs8-pem';
  if (/^-----BEGIN RSA PRIVATE KEY-----/m.test(text)) {
    return /Proc-Type:\s*4,ENCRYPTED/i.test(text) ? 'encrypted-pkcs8-pem' : 'pkcs1-pem';
  }
  if (/^-----BEGIN EC PRIVATE KEY-----/m.test(text)) return 'sec1-pem';
  if (/^-----BEGIN PUBLIC KEY-----/m.test(text)) return 'spki-pem';
  if (/^-----BEGIN RSA PUBLIC KEY-----/m.test(text)) return 'pkcs1-pub-pem';
  return 'unknown';
}

/**
 * Parse a PEM or DER key file buffer and return structured key data plus the
 * underlying crypto.KeyObject for subsequent export operations.
 *
 * For encrypted keys, `passphrase` must be provided; otherwise an error is thrown
 * that includes the string "passphrase required" so callers can detect it.
 */
export function parseKeyFile(
  buf: Buffer,
  passphrase?: string,
): { data: StandaloneKeyData; nodeKey: crypto.KeyObject } {
  const text = buf.toString('utf8').trim();
  const isPem = text.startsWith('-----BEGIN');

  let inputFormat: InputFormat;
  let kind: 'private' | 'public';
  let nodeKey: crypto.KeyObject;

  if (isPem) {
    inputFormat = detectPemFormat(text);
    const isPublicPem = inputFormat === 'spki-pem' || inputFormat === 'pkcs1-pub-pem';
    const isEncryptedPem = inputFormat === 'encrypted-pkcs8-pem';

    if (isPublicPem) {
      kind = 'public';
      try {
        nodeKey = crypto.createPublicKey(text);
      } catch (e) {
        throw new Error(`Failed to parse public key: ${(e as Error).message}`);
      }
    } else {
      kind = 'private';
      try {
        if (isEncryptedPem && passphrase === undefined) {
          throw new Error('Key is encrypted — passphrase required.');
        }
        nodeKey = passphrase !== undefined
          ? crypto.createPrivateKey({ key: text, passphrase })
          : crypto.createPrivateKey(text);
      } catch (e) {
        throw new Error(`Failed to parse private key: ${(e as Error).message}`);
      }
    }
  } else {
    // DER binary: try private formats, then SPKI public
    let parsed: crypto.KeyObject | undefined;
    let parsedKind: 'private' | 'public' = 'private';

    for (const type of ['pkcs8', 'pkcs1', 'sec1'] as const) {
      try {
        parsed = passphrase !== undefined
          ? crypto.createPrivateKey({ key: buf, format: 'der', type, passphrase })
          : crypto.createPrivateKey({ key: buf, format: 'der', type });
        break;
      } catch { /* try next */ }
    }

    if (!parsed) {
      try {
        parsed = crypto.createPublicKey({ key: buf, format: 'der', type: 'spki' });
        parsedKind = 'public';
      } catch {
        throw new Error('Could not parse key file — not a recognised private or public key format.');
      }
    }

    nodeKey = parsed;
    kind = parsedKind;
    inputFormat = parsedKind === 'public' ? 'spki-der' : 'der';
  }

  const isEncrypted = inputFormat === 'encrypted-pkcs8-pem';

  // Derive SPKI from private or public key
  const pubKey = kind === 'private' ? crypto.createPublicKey(nodeKey) : nodeKey;
  const spkiDer = pubKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const spkiPem = pubKey.export({ type: 'spki', format: 'pem' }) as string;

  // Key ID: SHA-1 of SPKI DER (matches X.509 SubjectKeyIdentifier)
  const keyId = bufToHex(crypto.createHash('sha1').update(spkiDer).digest());

  const keyType = nodeKey.asymmetricKeyType ?? 'unknown';
  const keyDetails = (nodeKey.asymmetricKeyDetails ?? {}) as Record<string, unknown>;

  const data: StandaloneKeyData = {
    kind,
    algorithm: ALG_DISPLAY[keyType] ?? keyType.toUpperCase(),
    isEncrypted,
    inputFormat,
    spkiPem,
    keyId,
  };

  if (typeof keyDetails.modulusLength === 'number') data.keySize = keyDetails.modulusLength;
  if (typeof keyDetails.namedCurve === 'string') {
    data.namedCurve = CURVE_DISPLAY[keyDetails.namedCurve] ?? keyDetails.namedCurve;
  }

  // RSA: extract modulus and public exponent via forge
  if (keyType === 'rsa' || keyType === 'rsa-pss') {
    try {
      const forgePub = forge.pki.publicKeyFromPem(spkiPem) as forge.pki.rsa.PublicKey;
      const nHex = (forgePub.n as unknown as { toString(r: number): string }).toString(16).toUpperCase();
      const eHex = (forgePub.e as unknown as { toString(r: number): string }).toString(16).toUpperCase();
      data.modulus = hexColons(nHex);
      data.publicExponent = hexColons(eHex);
    } catch { /* best-effort */ }
  }

  // Private key: export unencrypted PKCS#8 PEM for display
  if (kind === 'private') {
    data.pkcs8Pem = nodeKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  }

  return { data, nodeKey };
}

/**
 * Returns true if the buffer appears to be a passphrase-protected private key.
 */
export function isEncryptedKey(buf: Buffer): boolean {
  const text = buf.toString('utf8').trim();
  return (
    /^-----BEGIN ENCRYPTED PRIVATE KEY-----/m.test(text) ||
    (/^-----BEGIN (RSA|EC) PRIVATE KEY-----/m.test(text) && /Proc-Type:\s*4,ENCRYPTED/i.test(text))
  );
}

/**
 * Returns true if the buffer looks like a standalone key file (not a certificate or CSR).
 */
export function looksLikeKeyFile(buf: Buffer): boolean {
  const text = buf.toString('utf8').trim();
  return (
    text.startsWith('-----BEGIN PRIVATE KEY-----') ||
    text.startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----') ||
    text.startsWith('-----BEGIN RSA PRIVATE KEY-----') ||
    text.startsWith('-----BEGIN EC PRIVATE KEY-----') ||
    text.startsWith('-----BEGIN PUBLIC KEY-----') ||
    text.startsWith('-----BEGIN RSA PUBLIC KEY-----')
  );
}

/**
 * Generate a fresh asymmetric key pair asynchronously and return structured key
 * data for the private key, plus PEM strings for both keys.
 */
export function generateKeyPair(algorithm: KeyAlgorithm): Promise<{
  data: StandaloneKeyData;
  nodeKey: crypto.KeyObject;
  privateKeyPem: string;
  publicKeyPem: string;
}> {
  return new Promise((resolve, reject) => {
    const finish = (err: Error | null, pubKey?: crypto.KeyObject, privKey?: crypto.KeyObject) => {
      if (err || !pubKey || !privKey) { reject(err ?? new Error('Key generation failed')); return; }
      try {
        const privateKeyPem = privKey.export({ type: 'pkcs8', format: 'pem' }) as string;
        const publicKeyPem = pubKey.export({ type: 'spki', format: 'pem' }) as string;
        const { data } = parseKeyFile(Buffer.from(privateKeyPem, 'utf8'));
        resolve({ data, nodeKey: privKey, privateKeyPem, publicKeyPem });
      } catch (e) { reject(e); }
    };

    switch (algorithm) {
      case 'RSA-2048':
        crypto.generateKeyPair('rsa', { modulusLength: 2048 }, finish);
        break;
      case 'RSA-4096':
        crypto.generateKeyPair('rsa', { modulusLength: 4096 }, finish);
        break;
      case 'EC-P256':
        crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, finish);
        break;
      case 'EC-P384':
        crypto.generateKeyPair('ec', { namedCurve: 'P-384' }, finish);
        break;
      case 'EC-P521':
        crypto.generateKeyPair('ec', { namedCurve: 'P-521' }, finish);
        break;
    }
  });
}
