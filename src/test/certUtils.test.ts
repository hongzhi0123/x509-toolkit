import { bufToHex, parseDNString } from '../certUtils';

describe('bufToHex', () => {
  it('returns empty string for empty Uint8Array', () => {
    expect(bufToHex(new Uint8Array([]))).toBe('');
  });

  it('converts a single byte', () => {
    expect(bufToHex(new Uint8Array([0xab]))).toBe('ab');
  });

  it('pads a single-digit hex byte with a leading zero', () => {
    expect(bufToHex(new Uint8Array([0x0f]))).toBe('0f');
  });

  it('separates multiple bytes with colons', () => {
    expect(bufToHex(new Uint8Array([0x01, 0x02, 0xfe]))).toBe('01:02:fe');
  });

  it('converts a 4-byte Uint8Array', () => {
    expect(bufToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe('de:ad:be:ef');
  });

  it('accepts an ArrayBuffer', () => {
    const buf = new Uint8Array([0xca, 0xfe]).buffer;
    expect(bufToHex(buf)).toBe('ca:fe');
  });

  it('handles all-zero bytes', () => {
    expect(bufToHex(new Uint8Array([0x00, 0x00, 0x00]))).toBe('00:00:00');
  });

  it('handles max byte value 0xff', () => {
    expect(bufToHex(new Uint8Array([0xff, 0xff]))).toBe('ff:ff');
  });
});

describe('parseDNString', () => {
  it('stores the raw DN string', () => {
    const raw = 'CN=test.example.com';
    expect(parseDNString(raw).raw).toBe(raw);
  });

  it('parses CN', () => {
    expect(parseDNString('CN=test.example.com').commonName).toBe('test.example.com');
  });

  it('parses O (organization)', () => {
    expect(parseDNString('O=My Organization').organization).toBe('My Organization');
  });

  it('parses OU (organizational unit)', () => {
    expect(parseDNString('OU=Engineering').organizationalUnit).toBe('Engineering');
  });

  it('parses C (country)', () => {
    expect(parseDNString('C=US').country).toBe('US');
  });

  it('parses ST (state)', () => {
    expect(parseDNString('ST=California').state).toBe('California');
  });

  it('parses S as alias for ST', () => {
    expect(parseDNString('S=Texas').state).toBe('Texas');
  });

  it('parses L (locality)', () => {
    expect(parseDNString('L=San Francisco').locality).toBe('San Francisco');
  });

  it('parses E (email shorthand)', () => {
    expect(parseDNString('E=user@example.com').email).toBe('user@example.com');
  });

  it('parses EMAILADDRESS (case-insensitive key)', () => {
    expect(parseDNString('emailaddress=admin@corp.com').email).toBe('admin@corp.com');
  });

  it('parses DC (domain component)', () => {
    expect(parseDNString('DC=example').domainComponent).toBe('example');
  });

  it('parses UID (user id)', () => {
    expect(parseDNString('UID=johndoe').userId).toBe('johndoe');
  });

  it('parses a fully-specified DN with multiple attributes', () => {
    const dn = parseDNString('CN=My Cert, O=ACME Corp., OU=IT, C=DE, ST=Bavaria, L=Munich');
    expect(dn.commonName).toBe('My Cert');
    expect(dn.organization).toBe('ACME Corp.');
    expect(dn.organizationalUnit).toBe('IT');
    expect(dn.country).toBe('DE');
    expect(dn.state).toBe('Bavaria');
    expect(dn.locality).toBe('Munich');
  });

  it('trims whitespace around keys and values', () => {
    const dn = parseDNString('  CN  =  hello world  ,  O  =  Org  ');
    expect(dn.commonName).toBe('hello world');
    expect(dn.organization).toBe('Org');
  });

  it('silently ignores unrecognized attribute keys', () => {
    const dn = parseDNString('UNKNOWN=value, CN=hello');
    expect(dn.commonName).toBe('hello');
    expect(dn.domainComponent).toBeUndefined();
  });

  it('returns an object with only raw for an empty string', () => {
    const dn = parseDNString('');
    expect(dn.raw).toBe('');
    expect(dn.commonName).toBeUndefined();
  });
});
