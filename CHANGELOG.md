# Changelog

All notable changes to this project will be documented here.

---

## [0.6.0] - 2026-10-31

### Added

- Custom editors for certificate/CSR files (`.pem`, `.crt`, `.cer`, `.der`, `.csr`, `.req`)
- Custom editor for key files (`.key`, `.pk8`, `.p8`, `.pub`)
- Custom editor for CRL files (`.crl`)
- P12/PFX support in custom certificate editor (`.p12`, `.pfx`)
- Extension test coverage for custom editor association sync and setting-driven enable/disable behavior

### Changed

- Custom editor mode is now enabled by default
- New setting `x509toolkit.useCustomEditor.enabled` can disable custom editors and return to legacy open behavior

### Fixed

- Improved handoff behavior between custom editor types while preserving preview-tab behavior
- Improved reliability of encrypted-file passphrase prompts with fallback to VS Code input dialogs

## [0.5.0] - 2026-08-18

### Added

- Open certificate file via context menu
- Browse and open CAs
- Inspect TLS Server
- Conversion Hub
- CRL Viewer
- Load/Save CNF file for creating CSR
- Save content of CNF as default


## [0.2.0] - 2026-05-07

### Added

- Create/View/Sign CSR


## [0.1.0] - 2026-05-01

### Added

- Open PEM, DER, PKCS#7, PKCS#12, and PKCS#12/PFX files
- Show PEM from editor selection
- Open CAs using the link in the Authority Information Access (AIA) extension
- Export certificate
- Create a P12 file with private key and CA chains
- Create self-signed certificate
- Show details of qualified certificates extension
- Import corresponding private key
