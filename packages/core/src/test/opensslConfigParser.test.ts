import { parseOpenSslConfig, serializeOpenSslConfig } from '../parsers/opensslConfigParser';

const SAMPLE_CNF = `# Sample request config
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no
default_bits = 2048
default_days = 365
default_md = sha256

[ req_distinguished_name ]
CN = my-service.example.com
O = ACME Corp
OU = Engineering
C = US
ST = California
L = San Francisco
emailAddress = admin@example.com

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = example.com
DNS.2 = www.example.com
IP.1 = 10.0.0.1
`;

describe('parseOpenSslConfig', () => {
  it('maps every field from a full representative CNF', () => {
    const cfg = parseOpenSslConfig(SAMPLE_CNF);

    // DN
    expect(cfg.cn).toBe('my-service.example.com');
    expect(cfg.o).toBe('ACME Corp');
    expect(cfg.ou).toBe('Engineering');
    expect(cfg.c).toBe('US');
    expect(cfg.st).toBe('California');
    expect(cfg.l).toBe('San Francisco');
    expect(cfg.email).toBe('admin@example.com');

    // SANs
    expect(cfg.dnsNames).toBe('example.com\nwww.example.com');
    expect(cfg.ipAddresses).toBe('10.0.0.1');

    // Key / validity / hash
    expect(cfg.keyAlgorithm).toBe('RSA-2048');
    expect(cfg.validityDays).toBe(365);
    expect(cfg.defaultMd).toBe('sha256');

    // Extensions
    expect(cfg.isCA).toBe(false);
    expect(cfg.keyUsageDigitalSignature).toBe(true);
    expect(cfg.keyUsageKeyEncipherment).toBe(true);
    expect(cfg.keyUsageDataEncipherment).toBe(false);
    expect(cfg.keyUsageKeyCertSign).toBe(false);
    expect(cfg.keyUsageCRLSign).toBe(false);
    expect(cfg.ekuServerAuth).toBe(true);
    expect(cfg.ekuClientAuth).toBe(true);
    expect(cfg.ekuCodeSigning).toBe(false);
    expect(cfg.ekuEmailProtection).toBe(false);
  });

  it('supports inline subjectAltName (DNS/IP prefixes) in addition to @section', () => {
    const cfg = parseOpenSslConfig(`
[ req ]
req_extensions = v3_req
[ v3_req ]
subjectAltName = DNS:example.com, DNS:www.example.com, IP:10.0.0.1
`);
    expect(cfg.dnsNames).toBe('example.com\nwww.example.com');
    expect(cfg.ipAddresses).toBe('10.0.0.1');
  });

  it('defaults unlisted keyUsage / extendedKeyUsage tokens to false', () => {
    const cfg = parseOpenSslConfig(`
[ req ]
req_extensions = v3_req
[ v3_req ]
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
`);
    expect(cfg.keyUsageDigitalSignature).toBe(true);
    expect(cfg.keyUsageKeyEncipherment).toBe(false);
    expect(cfg.keyUsageDataEncipherment).toBe(false);
    expect(cfg.keyUsageKeyCertSign).toBe(false);
    expect(cfg.keyUsageCRLSign).toBe(false);
    expect(cfg.ekuServerAuth).toBe(true);
    expect(cfg.ekuClientAuth).toBe(false);
    expect(cfg.ekuCodeSigning).toBe(false);
    expect(cfg.ekuEmailProtection).toBe(false);
  });

  it('handles comments (# and ;), blank lines, and key=value without spaces', () => {
    const cfg = parseOpenSslConfig(`
; semicolon comment
[ req ]
# hash comment
req_extensions = v3_req
default_bits=2048

[ v3_req ]
basicConstraints=CA:TRUE ; trailing comment
keyUsage=keyCertSign, cRLSign
`);
    expect(cfg.keyAlgorithm).toBe('RSA-2048');
    expect(cfg.isCA).toBe(true);
    expect(cfg.keyUsageKeyCertSign).toBe(true);
    expect(cfg.keyUsageCRLSign).toBe(true);
  });

  it('treats a # inside a value as data, not a comment', () => {
    const cfg = parseOpenSslConfig(`
[ req_distinguished_name ]
CN = service#prod
`);
    expect(cfg.cn).toBe('service#prod');
  });

  it('yields no SAN fields when the extension section or alt_names section is missing', () => {
    const noExt = parseOpenSslConfig('[ req ]\ndefault_bits = 2048\n');
    expect(noExt.dnsNames).toBeUndefined();
    expect(noExt.ipAddresses).toBeUndefined();

    const noAlt = parseOpenSslConfig(`
[ req ]
req_extensions = v3_req
[ v3_req ]
subjectAltName = @alt_names
`);
    expect(noAlt.dnsNames).toBeUndefined();
    expect(noAlt.ipAddresses).toBeUndefined();
  });

  it('does not throw on malformed input', () => {
    expect(() => parseOpenSslConfig('this is not a config\n')).not.toThrow();
    expect(() => parseOpenSslConfig('[unclosed section\nkey only line\n')).not.toThrow();
    expect(parseOpenSslConfig('garbage without sections or equals')).toEqual({});
  });

  it('returns an empty object for an empty/unrecognized file', () => {
    expect(parseOpenSslConfig('')).toEqual({});
    expect(parseOpenSslConfig('\n\n# only comments\n')).toEqual({});
  });

  it('maps default_bits to keyAlgorithm and omits it when absent', () => {
    expect(parseOpenSslConfig('[ req ]\ndefault_bits = 4096\n').keyAlgorithm).toBe('RSA-4096');
    expect(parseOpenSslConfig('[ req ]\ndefault_bits = 2048\n').keyAlgorithm).toBe('RSA-2048');
    expect(parseOpenSslConfig('[ req ]\ndefault_bits = 3072\n').keyAlgorithm).toBe('RSA-2048');
    expect(parseOpenSslConfig('[ req ]\n').keyAlgorithm).toBeUndefined();
    expect(parseOpenSslConfig('').keyAlgorithm).toBeUndefined();
  });

  it('maps basicConstraints CA:TRUE (case-insensitive) to isCA', () => {
    expect(parseOpenSslConfig('[ v3_req ]\nbasicConstraints = CA:TRUE\n').isCA).toBe(true);
    expect(parseOpenSslConfig('[ v3_req ]\nbasicConstraints = critical, ca:true\n').isCA).toBe(true);
    expect(parseOpenSslConfig('[ v3_req ]\nbasicConstraints = CA:FALSE\n').isCA).toBe(false);
  });

  it('honours the req_extensions section name and strips a leading @', () => {
    const cfg = parseOpenSslConfig(`
[ req ]
req_extensions = my_ext
[ my_ext ]
extendedKeyUsage = codeSigning
`);
    expect(cfg.ekuCodeSigning).toBe(true);
    expect(cfg.ekuServerAuth).toBe(false);

    const atRef = parseOpenSslConfig(`
[ req ]
req_extensions = @my_ext
[ my_ext ]
keyUsage = dataEncipherment
`);
    expect(atRef.keyUsageDataEncipherment).toBe(true);
    expect(atRef.keyUsageDigitalSignature).toBe(false);
  });

  it('reads DN keys case-insensitively and removes surrounding quotes', () => {
    const cfg = parseOpenSslConfig(`
[ req_distinguished_name ]
cn = "quoted name"
O = 'ACME'
`);
    expect(cfg.cn).toBe('quoted name');
    expect(cfg.o).toBe('ACME');
  });

  it('maps standard long-form OpenSSL distinguished-name attributes', () => {
    const cfg = parseOpenSslConfig(`
[ req_distinguished_name ]
countryName = US
stateOrProvinceName = California
localityName = San Francisco
organizationName = Example Corp
organizationalUnitName = IT Department
commonName = example.com
emailAddress = admin@example.com
`);

    expect(cfg.c).toBe('US');
    expect(cfg.st).toBe('California');
    expect(cfg.l).toBe('San Francisco');
    expect(cfg.o).toBe('Example Corp');
    expect(cfg.ou).toBe('IT Department');
    expect(cfg.cn).toBe('example.com');
    expect(cfg.email).toBe('admin@example.com');
  });

  it('serializes form settings as a config the parser can read', () => {
    const serialized = serializeOpenSslConfig({
      cn: 'example.com', o: 'Example Corp', ou: 'IT', c: 'US', st: 'California', l: 'San Francisco', email: 'admin@example.com',
      dnsNames: 'example.com\nwww.example.com', ipAddresses: '192.168.1.1', keyAlgorithm: 'RSA-4096',
      isCA: false, keyUsageDigitalSignature: true, keyUsageKeyEncipherment: true, keyUsageDataEncipherment: false,
      keyUsageKeyCertSign: false, keyUsageCRLSign: false, ekuServerAuth: true, ekuClientAuth: true,
      ekuCodeSigning: false, ekuEmailProtection: false,
    });

    expect(serialized).toContain('commonName = example.com');
    expect(serialized).toContain('default_bits = 4096');
    expect(parseOpenSslConfig(serialized)).toMatchObject({
      cn: 'example.com', o: 'Example Corp', ou: 'IT', c: 'US', st: 'California', l: 'San Francisco',
      dnsNames: 'example.com\nwww.example.com', ipAddresses: '192.168.1.1', keyAlgorithm: 'RSA-4096',
    });
  });

  it('preserves numeric order of DNS.1/DNS.2/IP.1 entries', () => {
    const cfg = parseOpenSslConfig(`
[ req ]
req_extensions = v3_req
[ v3_req ]
subjectAltName = @alt_names
[ alt_names ]
DNS.10 = ten.example.com
DNS.2 = two.example.com
IP.2 = 10.0.0.2
IP.1 = 10.0.0.1
`);
    expect(cfg.dnsNames).toBe('two.example.com\nten.example.com');
    expect(cfg.ipAddresses).toBe('10.0.0.1\n10.0.0.2');
  });

  it('omits default_days when it is not a positive integer', () => {
    expect(parseOpenSslConfig('[ req ]\ndefault_days = 0\n').validityDays).toBeUndefined();
    expect(parseOpenSslConfig('[ req ]\ndefault_days = -5\n').validityDays).toBeUndefined();
    expect(parseOpenSslConfig('[ req ]\ndefault_days = abc\n').validityDays).toBeUndefined();
    expect(parseOpenSslConfig('[ req ]\ndefault_days = 90\n').validityDays).toBe(90);
  });
});
