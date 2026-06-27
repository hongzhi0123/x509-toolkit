# X.509 Toolkit — Copilot Workspace Instructions

## Project Overview

**X.509 Certificate Toolkit** is a VS Code extension (publisher: `hongzhi0123`) that parses and displays X.509 certificates from PEM, DER, and PKCS#12/PFX/P12 files. It also supports creating self-signed and CA-signed certificates. The extension is packaged as a `.vsix` and targets VS Code ≥ 1.85.

---

## Architecture: Two Distinct Runtimes

The project is split into two independently compiled halves that communicate exclusively via VS Code's webview message API.

### 1. Extension Host (`src/`)
- Runs in Node.js inside VS Code's extension host process.
- Compiled with **webpack** (`webpack.config.js`) → `dist/extension.js`.
- Entry point: `src/extension.ts`.
- Has access to VS Code API, Node.js built-ins (`fs`, `crypto`, `https`), and npm packages.

### 2. Webview UI (`webview-ui/`)
- Runs in a sandboxed browser context (Chromium) inside a VS Code `WebviewPanel`.
- Built with **Vite + Svelte 4** → `dist/webview/main.js` + `dist/webview/styles.css`.
- Entry point: `webview-ui/src/main.ts` → `webview-ui/src/App.svelte`.
- Has NO access to Node.js or VS Code APIs — uses `acquireVsCodeApi()` to post/receive messages.

---

## Source File Map (`src/`)

| File | Responsibility |
|------|---------------|
| `extension.ts` | Registers all VS Code commands; orchestrates file open dialogs, text selection parsing, and panel lifecycle |
| `panelManager.ts` | Creates/reuses the single certificate viewer `WebviewPanel`; handles all webview↔extension messaging (including the passphrase request bridge and CA issuer cert download via HTTP/HTTPS) |
| `createCertPanel.ts` | Creates/manages the separate "Create Certificate" `WebviewPanel`; handles CA cert/key file pickers and calls `generateCertificate` |
| `certificateParser.ts` | Core parser — uses `@peculiar/x509` + `@peculiar/webcrypto` to parse a single DER/PEM certificate buffer into a `CertificateData` object; also exposes `parsePEMChain` for multi-cert PEM blocks |
| `p12Parser.ts` | Uses `node-forge` to open PKCS#12/PFX files; matches private keys to certs using `localKeyId`; also contains `generateCertificate` (creates RSA/EC certs with `@peculiar/x509`) and `createP12Buffer` / `loadAndValidatePrivateKey` helpers |
| `certUtils.ts` | Pure helper utilities: `bufToHex` (produces `aa:bb:cc` hex strings) and `parseDNString` (parses DN strings into `DistinguishedName`) |
| `derUtils.ts` | Minimal DER/TLV reader: `derTLV`, `derOid`, `derInt`, `derStr` — used for bespoke extension parsing without a full ASN.1 library |
| `oidMaps.ts` | Static lookup tables: `EXT_NAMES` (extension OID → human name), `EKU_NAMES`, `SIG_ALG_NAMES` |
| `qcStatements.ts` | Parser for the QC Statements extension (OID 1.3.6.1.5.5.7.1.3), including ETSI EN 319 412-5 and PSD2 role names |
| `types.ts` | **Shared type definitions** — kept free of Node.js/VS Code imports so they can be mirrored verbatim in the webview. Contains `CertificateData`, `CertExtension`, `PrivateKeyInfo`, `CertCreateParams`, and the full message protocol types (`ExtToWebviewMsg`, `WebviewToExtMsg`, `CreateCertToExtMsg`, `ExtToCreateCertMsg`) |

---

## Webview UI File Map (`webview-ui/src/`)

| File | Responsibility |
|------|---------------|
| `App.svelte` | Root component — owns the app state machine (`idle/loading/ready/error`), the certificate chain array, active index, downloaded CA issuer certs, imported private keys, and the passphrase dialog state. Handles all incoming extension messages |
| `lib/CertificateView.svelte` | Renders all fields for the active `CertificateData`: subject/issuer DN, validity, public key, extensions, fingerprints, raw PEM, private key section |
| `lib/CreateCertPanel.svelte` | The certificate creation form (key algorithm, DN fields, SANs, key usage, EKU, validity, signing mode, password) |
| `lib/ExtensionsList.svelte` | Renders the list of certificate extensions |
| `lib/FieldRow.svelte` | Generic label/value row used throughout the UI |
| `lib/HexValue.svelte` | Renders a colon-separated hex string with copy-to-clipboard |
| `lib/Fingerprints.svelte` | Renders SHA-1 and SHA-256 fingerprints with copy button |
| `lib/PassphraseDialog.svelte` | Modal dialog for the passphrase request flow; responds to `requestPassphrase` messages |
| `lib/SectionCard.svelte` | Collapsible card wrapper for groups of fields |
| `lib/ValidityIndicator.svelte` | Color-coded validity badge (valid / expiring soon / expired) |
| `types.ts` | Mirror of `src/types.ts` — **must be kept in sync manually** |

---

## Message Protocol

All communication between the extension host and webview uses typed discriminated unions defined in `src/types.ts`.

**Extension → Viewer Webview** (`ExtToWebviewMsg`):
- `loading` — clears the panel, shows spinner
- `certificate` — sends `CertificateData[]` chain + `activeIndex`
- `error` — displays error message
- `caIssuerCert` / `caIssuerError` — result of downloading a CA issuer cert from an AIA URL
- `privateKeyImported` / `privateKeyImportError` — result of importing a private key into a cert slot
- `requestPassphrase` — triggers the in-panel passphrase dialog (identified by `requestId`)

**Viewer Webview → Extension** (`WebviewToExtMsg`):
- `ready` — webview is initialised
- `copyToClipboard` — asks extension to write text to the clipboard
- `fetchCaIssuerCert` — asks extension to download a cert from a URL
- `importPrivateKey` — asks extension to load a private key file
- `passphraseResponse` — returns the passphrase (or `null` for cancel) matching a `requestId`

**Create Cert Webview ↔ Extension** (`CreateCertToExtMsg` / `ExtToCreateCertMsg`):
- Separate panel/message types for the certificate generation workflow.

---

## Key Dependencies

| Package | Used by | Purpose |
|---------|---------|---------|
| `@peculiar/x509` | Extension host | RFC 5280–compliant X.509 parsing and certificate generation |
| `@peculiar/webcrypto` | Extension host | WebCrypto polyfill for Node.js (required by `@peculiar/x509`) |
| `node-forge` | Extension host | PKCS#12 parsing; provides stronger P12 compatibility |
| `svelte` | Webview | UI framework |
| `vite` | Webview | Build tool |
| `webpack` + `ts-loader` | Extension host | Bundle extension code |
| `jest` + `ts-jest` | Tests | Unit test runner |

---

## Build System

```
npm run build          # Full build: webview then extension
npm run build:webview  # cd webview-ui && npm run build  →  dist/webview/
npm run build:ext      # webpack --mode production       →  dist/extension.js
npm run watch:ext      # webpack --watch (development)
npm run watch:webview  # vite dev server (development)
npm test               # jest (unit tests only, no VS Code runtime needed)
npm run package        # vsce package → .vsix
```

Build outputs all land in `dist/`:
- `dist/extension.js` — bundled extension host
- `dist/webview/main.js` — bundled webview JS (IIFE)
- `dist/webview/styles.css` — webview styles

---

## VS Code Commands

| Command ID | Title |
|-----------|-------|
| `x509toolkit.showFromSelection` | Show Certificate from Selection (editor context menu) |
| `x509toolkit.openFile` | Open Certificate File (PEM/DER/PFX dialog) |
| `x509toolkit.openP12` | Open P12 / PFX File |
| `x509toolkit.createSelfSignedP12` | Create Self-Signed P12 (legacy) |
| `x509toolkit.createCertificate` | Create Certificate (opens `CreateCertPanel`) |

---

## Testing

Unit tests live in `src/test/` and use **Jest** with `ts-jest`. They test the parsing logic directly without requiring a VS Code extension host. Configuration is in `jest.config.js` and `tsconfig.test.json`.

Test files mirror their source:
- `certificateParser.test.ts` — tests `parseCertificate`, `parsePEMChain`
- `certUtils.test.ts` — tests `bufToHex`, `parseDNString`
- `derUtils.test.ts` — tests `derTLV`, `derOid`, `derInt`, `derStr`
- `oidMaps.test.ts` — tests OID lookup maps
- `p12Parser.test.ts` — tests `parseP12`, `generateCertificate`
- `qcStatements.test.ts` — tests `parseQcStatements`

---

## Important Conventions

- **`src/types.ts` and `webview-ui/src/types.ts` must stay in sync.** There is no code-sharing between the two build targets; types are duplicated by design.
- Hex values throughout the codebase use colon-separated uppercase format (`AA:BB:CC`), produced by `certUtils.bufToHex`.
- The passphrase dialog is rendered inside the webview (not a native VS Code input box) to avoid the webview losing focus; it uses a `requestId` round-trip.
- `panelManager.ts` enforces a single viewer panel instance (`currentPanel`); `createCertPanel.ts` enforces a single create-cert panel (`createCertPanelRef`).
- The webview HTML is generated inline in `panelManager.ts` / `createCertPanel.ts` using a `buildHtml()` helper that injects a CSP nonce and the correct `dist/webview` URIs.
