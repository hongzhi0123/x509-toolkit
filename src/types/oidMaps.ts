import {
  id_ce_subjectDirectoryAttributes, id_ce_subjectKeyIdentifier, id_ce_keyUsage,
  id_ce_privateKeyUsagePeriod, id_ce_subjectAltName, id_ce_issuerAltName,
  id_ce_basicConstraints, id_ce_cRLNumber, id_ce_cRLReasons,
  id_ce_invalidityDate, id_ce_deltaCRLIndicator, id_ce_issuingDistributionPoint,
  id_ce_certificateIssuer, id_ce_nameConstraints, id_ce_cRLDistributionPoints,
  id_ce_certificatePolicies, id_ce_policyMappings, id_ce_authorityKeyIdentifier,
  id_ce_policyConstraints, id_ce_extKeyUsage, id_ce_freshestCRL,
  id_ce_inhibitAnyPolicy, id_pe_authorityInfoAccess, id_pe_subjectInfoAccess,
  id_kp_serverAuth, id_kp_clientAuth, id_kp_codeSigning, id_kp_emailProtection,
  id_kp_timeStamping, id_kp_OCSPSigning, anyExtendedKeyUsage,
} from '@peculiar/asn1-x509';
import { id_pe_qcStatements } from '@peculiar/asn1-x509-qualified';
import {
  id_md5WithRSAEncryption, id_sha1WithRSAEncryption,
  id_sha256WithRSAEncryption, id_sha384WithRSAEncryption, id_sha512WithRSAEncryption,
  id_RSASSA_PSS,
} from '@peculiar/asn1-rsa';
import {
  id_ecdsaWithSHA224, id_ecdsaWithSHA256, id_ecdsaWithSHA384, id_ecdsaWithSHA512,
} from '@peculiar/asn1-ecc';

export const EXT_NAMES: Record<string, string> = {
  [id_ce_subjectDirectoryAttributes]: 'Subject Directory Attributes',
  [id_ce_subjectKeyIdentifier]:       'Subject Key Identifier',
  [id_ce_keyUsage]:                   'Key Usage',
  [id_ce_privateKeyUsagePeriod]:      'Private Key Usage Period',
  [id_ce_subjectAltName]:             'Subject Alternative Names',
  [id_ce_issuerAltName]:              'Issuer Alternative Name',
  [id_ce_basicConstraints]:           'Basic Constraints',
  [id_ce_cRLNumber]:                  'CRL Number',
  [id_ce_cRLReasons]:                 'Reason Code',
  '2.5.29.23':                        'Hold Instruction Code',
  [id_ce_invalidityDate]:             'Invalidity Date',
  [id_ce_deltaCRLIndicator]:          'Delta CRL Indicator',
  [id_ce_issuingDistributionPoint]:   'Issuing Distribution Point',
  [id_ce_certificateIssuer]:          'Certificate Issuer',
  [id_ce_nameConstraints]:            'Name Constraints',
  [id_ce_cRLDistributionPoints]:      'CRL Distribution Points',
  [id_ce_certificatePolicies]:        'Certificate Policies',
  [id_ce_policyMappings]:             'Policy Mappings',
  [id_ce_authorityKeyIdentifier]:     'Authority Key Identifier',
  [id_ce_policyConstraints]:          'Policy Constraints',
  [id_ce_extKeyUsage]:                'Extended Key Usage',
  [id_ce_freshestCRL]:                'Freshest CRL',
  [id_ce_inhibitAnyPolicy]:           'Inhibit Any Policy',
  [id_pe_authorityInfoAccess]:        'Authority Information Access',
  [id_pe_qcStatements]:               'QC Statements',
  [id_pe_subjectInfoAccess]:          'Subject Information Access',
  '0.4.0.19495.2':                    'PSD2 QcStatement',
  '1.3.6.1.4.1.11129.2.4.2':          'Certificate Transparency SCTs',
  '1.3.6.1.4.1.11129.2.4.3':          'CT Poison',
};

export const EKU_NAMES: Record<string, string> = {
  [id_kp_serverAuth]:                 'TLS Server Authentication',
  [id_kp_clientAuth]:                 'TLS Client Authentication',
  [id_kp_codeSigning]:                'Code Signing',
  [id_kp_emailProtection]:            'Email Protection',
  [id_kp_timeStamping]:               'Time Stamping',
  [id_kp_OCSPSigning]:                'OCSP Signing',
  [anyExtendedKeyUsage]:              'Any Extended Key Usage',
  '1.3.6.1.4.1.311.10.3.3':           'Microsoft SGC',
  '2.16.840.1.113730.4.1':            'Netscape SGC',
};

/** OID → human-readable label for Distinguished Name attributes (X.500 / LDAP) */
export const DN_ATTR_NAMES: Record<string, string> = {
  // Core X.500 attribute types (2.5.4.x)
  '2.5.4.3':  'Common Name',
  '2.5.4.4':  'Surname',
  '2.5.4.5':  'Serial Number',
  '2.5.4.6':  'Country',
  '2.5.4.7':  'Locality',
  '2.5.4.8':  'State or Province',
  '2.5.4.9':  'Street Address',
  '2.5.4.10': 'Organization',
  '2.5.4.11': 'Organizational Unit',
  '2.5.4.12': 'Title',
  '2.5.4.13': 'Description',
  '2.5.4.15': 'Business Category',
  '2.5.4.17': 'Postal Code',
  '2.5.4.20': 'Telephone Number',
  '2.5.4.41': 'Name',
  '2.5.4.42': 'Given Name',
  '2.5.4.43': 'Initials',
  '2.5.4.44': 'Generation Qualifier',
  '2.5.4.46': 'DN Qualifier',
  '2.5.4.65': 'Pseudonym',
  '2.5.4.97': 'Organization Identifier',
  // LDAP / RFC 4519
  '0.9.2342.19200300.100.1.1':  'User ID',
  '0.9.2342.19200300.100.1.25': 'Domain Component',
  // PKCS#9
  '1.2.840.113549.1.9.1': 'Email Address',
  // EV certificate jurisdiction attributes (Microsoft / CA/Browser Forum)
  '1.3.6.1.4.1.311.60.2.1.1': 'Jurisdiction Locality',
  '1.3.6.1.4.1.311.60.2.1.2': 'Jurisdiction State',
  '1.3.6.1.4.1.311.60.2.1.3': 'Jurisdiction Country',
};

export const SIG_ALG_NAMES: Record<string, string> = {
  [id_md5WithRSAEncryption]:    'MD5 with RSA',
  [id_sha1WithRSAEncryption]:   'SHA-1 with RSA',
  [id_sha256WithRSAEncryption]: 'SHA-256 with RSA',
  [id_sha384WithRSAEncryption]: 'SHA-384 with RSA',
  [id_sha512WithRSAEncryption]: 'SHA-512 with RSA',
  [id_RSASSA_PSS]:              'RSASSA-PSS',
  [id_ecdsaWithSHA224]:         'ECDSA with SHA-224',
  [id_ecdsaWithSHA256]:         'ECDSA with SHA-256',
  [id_ecdsaWithSHA384]:         'ECDSA with SHA-384',
  [id_ecdsaWithSHA512]:         'ECDSA with SHA-512',
  '1.3.101.112':                'Ed25519',
  '1.3.101.113':                'Ed448',
};
