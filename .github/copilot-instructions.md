# X.509 Toolkit — Copilot Workspace Instructions

## Project Overview

**X.509 Certificate Toolkit** is a VS Code extension (publisher: `hongzhi0123`) that parses and displays X.509 certificates, CRLs, and private/public keys from PEM, DER, PKCS#12/PFX/P12, and key files. It also supports creating self-signed and CA-signed certificates, generating key pairs, inspecting live TLS server certificates, and converting between certificate formats. The extension is packaged as a `.vsix` and targets VS Code ≥ 1.85.

---

## Monorepo Structure

The project is an **npm workspace monorepo** rooted at the workspace root. All packages live under `packages/`:

```
packages/
  core/        — @x509-toolkit/core (pure library: parsers, types, utilities)
  extension/   — VS Code extension host (webpack bundle)
  webview-ui/  — Svelte webview UI (Vite bundle)
```

---

## Architecture: Three Independent Runtimes

### 1. Core Library (`packages/core/`)
- Pure TypeScript — no VS Code or DOM dependencies.
- Built with **`tsc`** → `packages/core/dist/`.
- Published internally as `@x509-toolkit/core`; consumed by both the extension host and (via re-export) the webview.
- Contains all parsers, shared types, and utility functions.

### 2. Extension Host (`packages/extension/`)
- Runs in Node.js inside VS Code's extension host process.
- Compiled with **webpack** (`webpack.config.js`) → `packages/extension/dist/extension.js`.
- Entry point: `packages/extension/src/extension.ts`.
- Depends on `@x509-toolkit/core`, VS Code API, Node.js built-ins (`fs`, `tls`, `https`).

### 3. Webview UI (`packages/webview-ui/`)
- Runs in a sandboxed browser context (Chromium) inside VS Code `WebviewPanel`s.
- Built with **Vite + Svelte 4** → `packages/webview-ui/dist/`.
- Entry point: `packages/webview-ui/src/main.ts` — routes to the correct panel component based on `data-view` attribute.
- Has NO access to Node.js or VS Code APIs — uses `acquireVsCodeApi()` to post/receive messages.
- Types are imported directly from `@x509-toolkit/core` via a thin re-export in `types.ts`.

---

## Core Library File Map (`packages/core/src/`)

### `types/`
| File | Responsibility |
|------|---------------|
| `types.ts` | **Canonical shared type definitions** — all data shapes (`CertificateData`, `CsrData`, `CrlData`, `StandaloneKeyData`, `TlsConnectionInfo`, etc.) and the complete message protocol discriminated unions for every panel |
| `oidMaps.ts` | Static lookup tables: `EXT_NAMES` (extension OID → human name), `EKU_NAMES`, `SIG_ALG_NAMES`, `DN_ATTR_NAMES` |
| `qcEuPsd2.ts` | ETSI PSD2/QC statement type definitions and role name mappings |

### `parsers/`
| File | Responsibility |
|------|---------------|
| `certificateParser.ts` | `parseCertificate()`, `parsePEMChain()`, `parseCsr()` — uses `@peculiar/x509` + `@peculiar/webcrypto` |
| `crlParser.ts` | `parseCrl()` — parses PEM/DER Certificate Revocation Lists into `CrlData` |
| `keyParser.ts` | `parseKeyFile()`, `isEncryptedKey()`, `generateKeyPair()` — key loading and generation using Node.js `crypto` |
| `p12Parser.ts` | `parseP12()`, `createSelfSignedP12()`, `generateCertificate()`, `generateCsr()`, `createP12Buffer()` — PKCS#12 via `node-forge` + `@peculiar/x509` |
| `qcStatements.ts` | `QcStatementsExtension` class — parses OID 1.3.6.1.5.5.7.1.3 (ETSI EN 319 412-5 and PSD2) |

### `utils/`
| File | Responsibility |
|------|---------------|
| `certUtils.ts` | `bufToHex()` (produces `AA:BB:CC` hex), `parseDNString()` |
| `derUtils.ts` | Minimal DER/TLV reader: `derTLV`, `derOid`, `derInt`, `derStr` |
| `caChainUtils.ts` | Utilities for building and walking CA certificate chains |

---

## Extension Host File Map (`packages/extension/src/`)

### `extension.ts`
Registers all VS Code commands via `context.subscriptions`.

### `commands/`
| File | Responsibility |
|------|---------------|
| `showFromSelection.ts` | Parses selected editor text and opens the main viewer |
| `openFile.ts` | File open dialog for PEM/DER/PFX/key/CRL files; routes to the appropriate panel |
| `openFromExplorer.ts` | Explorer context menu handler — opens the selected file with the correct panel |
| `inspectTlsServer.ts` | Prompts for host:port, performs TLS handshake via Node.js `tls` module, displays the peer chain |
| `convertFormat.ts` | Opens the Format Conversion Hub panel |

### `panels/`
| File | Responsibility |
|------|---------------|
| `mainViewerPanel.ts` | Main certificate/CSR viewer `WebviewPanel`; handles chain display, passphrase bridge, CA issuer download, private key import, and message routing |
| `createCertPanel.ts` | Certificate/CSR generation panel; handles CA cert/key file pickers and calls `generateCertificate` / `generateCsr` |
| `crlPanel.ts` | CRL viewer `WebviewPanel` |
| `keyPanel.ts` | Standalone key viewer `WebviewPanel`; handles passphrase bridge for encrypted keys |
| `keyGenPanel.ts` | Key generation panel; handles save dialogs and input dialogs |
| `convertPanel.ts` | Format Conversion Hub panel; handles file picking and conversion operations |

### `utils/`
| File | Responsibility |
|------|---------------|
| `handleX509Input.ts` | Adapts parser output to panel messaging; routes parsed data to the correct panel |
| `fileActionsUtils.ts` | Shared helpers for file save dialogs and file I/O |
| `keyImportUtils.ts` | Helpers for importing private key files into certificate slots |
| `messageRouterUtils.ts` | Routes incoming `WebviewToExtMsg` messages to the correct handler |
| `requestBridgeUtils.ts` | Implements the `requestId`-keyed Promise bridge for passphrase and input-dialog round-trips |
| `webviewPanelUtils.ts` | Shared `buildHtml()` helper that injects a CSP nonce and the correct `dist/webview` URIs |

---

## Webview UI File Map (`packages/webview-ui/src/`)

### `panels/` — top-level view coordinators (use `acquireVsCodeApi()`)
| File | Responsibility |
|------|---------------|
| `App.svelte` | Main cert/CSR viewer — owns state machine (`idle/loading/ready/error`), cert chain, active index, CA issuer certs, imported private keys, passphrase/input-dialog state |
| `CreateCertPanel.svelte` | Certificate/CSR creation form (algorithm, DN, SANs, key usage, EKU, validity, signing mode, password) |
| `CrlView.svelte` | CRL viewer — displays `CrlData` including revoked certificate list |
| `KeyViewer.svelte` | Standalone key display and export |
| `KeyGenPanel.svelte` | Key generation form and result display |
| `ConvertHub.svelte` | Format conversion hub — file slot management and conversion operations |

### `lib/` — pure UI components (no `acquireVsCodeApi`)
| File | Responsibility |
|------|---------------|
| `CertificateView.svelte` | Renders all fields for a `CertificateData`: DN, validity, public key, extensions, fingerprints, raw PEM, private key section |
| `CsrView.svelte` | Renders CSR fields from `CsrData` |
| `ExtensionsList.svelte` | Renders the list of certificate extensions |
| `FieldRow.svelte` | Generic label/value row |
| `HexValue.svelte` | Colon-separated hex string with copy-to-clipboard |
| `Fingerprints.svelte` | SHA-1 and SHA-256 fingerprints with copy button |
| `PassphraseDialog.svelte` | Modal for passphrase requests (`requestPassphrase` messages) |
| `InputDialog.svelte` | Generic multi-field modal for `requestInputDialog` messages |
| `SectionCard.svelte` | Collapsible card wrapper |
| `ValidityIndicator.svelte` | Color-coded validity badge (valid / expiring soon / expired) |

### `types.ts`
Re-exports everything from `@x509-toolkit/core` — **not a manual mirror**. No duplication needed.

---

## Message Protocol

All panel communication uses typed discriminated unions defined in `packages/core/src/types/types.ts`.

**Main Viewer** (`ExtToWebviewMsg` / `WebviewToExtMsg`):
- Ext → Webview: `loading`, `tlsProgress`, `certificate` (chain + optional `TlsConnectionInfo`), `csr`, `error`, `caIssuerCert`, `caIssuerError`, `privateKeyImported`, `privateKeyImportError`, `requestPassphrase`, `requestInputDialog`
- Webview → Ext: `ready`, `copyToClipboard`, `selectCert`, `downloadCaIssuer`, `exportCert`, `exportPrivateKey`, `createP12`, `importPrivateKey`, `openCaCertFile`, `signCsr`, `saveCsrFile`, `savePrivateKey`, `saveBothFiles`, `passphraseResponse`, `inputDialogResponse`, `openConvertHub`

**Create Cert Panel** (`CreateCertToExtMsg` / `ExtToCreateCertMsg`):
- Webview → Ext: `ready`, `pickCaCert`, `pickCaKey`, `generate`, `generateCsr`, `saveCsrFile`, `savePrivateKey`, `cancel`, `inputDialogResponse`
- Ext → Webview: `caCertLoaded`, `caKeyLoaded`, `generating`, `done`, `csrReady`, `error`, `requestInputDialog`

**CRL Viewer** (`CrlViewerToExtMsg` / `ExtToCrlViewerMsg`):
- Webview → Ext: `crlViewerReady`, `copyToClipboard`
- Ext → Webview: `crlLoading`, `crlData`, `crlError`

**Key Viewer** (`KeyViewerToExtMsg` / `ExtToKeyViewerMsg`):
- Webview → Ext: `keyViewerReady`, `copyToClipboard`, `exportPrivateKey`, `exportPublicKey`, `passphraseResponse`, `inputDialogResponse`
- Ext → Webview: `keyLoading`, `keyData`, `keyError`, `requestPassphrase`, `requestInputDialog`

**Key Generator** (`KeyGenToExtMsg` / `ExtToKeyGenMsg`):
- Webview → Ext: `keyGenReady`, `keyGenGenerate`, `keyGenSavePrivateKey`, `keyGenSavePublicKey`, `keyGenViewKey`, `copyToClipboard`, `inputDialogResponse`
- Ext → Webview: `keyGenGenerating`, `keyGenDone`, `keyGenError`, `requestInputDialog`

**Format Conversion Hub** (`ConvertToExtMsg` / `ExtToConvertMsg`):
- Webview → Ext: `convertReady`, `convertPickFile`, `convertPickFiles`, `convertExecuteExtractP12`, `convertExecuteBuildP12`, `convertExecuteConvertFormat`, `convertExecuteBundleChain`
- Ext → Webview: `convertFileSelected`, `convertResult`, `convertError`

---

## Key Dependencies

| Package | Used by | Purpose |
|---------|---------|---------|
| `@peculiar/x509` | `@x509-toolkit/core` | RFC 5280–compliant X.509 parsing and generation |
| `@peculiar/webcrypto` | `@x509-toolkit/core` | WebCrypto polyfill for Node.js |
| `@peculiar/asn1-*` | `@x509-toolkit/core` | ASN.1 schemas (x509-qualified, x509-qualified-etsi, rsa, ecc, schema) |
| `node-forge` | `@x509-toolkit/core` | PKCS#12 parsing (stronger P12 compatibility) |
| `svelte` | `packages/webview-ui` | UI framework |
| `vite` | `packages/webview-ui` | Build tool |
| `webpack` + `ts-loader` | `packages/extension` | Bundle extension host code |
| `jest` + `ts-jest` | `packages/core` | Unit test runner |

---

## Build System

Run from the **workspace root**:

```
npm run build           # Full build: core → webview-ui → extension
npm run build:core      # tsc in packages/core       →  packages/core/dist/
npm run build:webview   # vite build in packages/webview-ui
npm run build:ext       # webpack in packages/extension →  packages/extension/dist/extension.js
npm run watch:ext       # webpack --watch (extension, development)
npm run watch:webview   # vite dev server (webview, development)
npm test                # jest in packages/core + jest in packages/extension
npm run test:core       # jest in packages/core only
npm run test:ext        # jest in packages/extension only
npm run test:e2e:ui     # build + run Playwright UI E2E tests
npm run package         # full build + vsce package → .vsix
```

---

## VS Code Commands

| Command ID | Title |
|-----------|-------|
| `x509toolkit.showFromSelection` | Show X.509 from Selection (editor context menu) |
| `x509toolkit.openFile` | Open X.509 File (PEM/DER/PFX/key/CRL dialog) |
| `x509toolkit.openFromExplorer` | Open with X.509 Toolkit (Explorer context menu) |
| `x509toolkit.createSelfSignedP12` | Create Self-Signed P12 (legacy) |
| `x509toolkit.createCertificate` | Create Certificate (opens `CreateCertPanel`) |
| `x509toolkit.inspectTlsServer` | Inspect TLS Server Certificate |
| `x509toolkit.convertFormat` | Convert Certificate Format (opens `ConvertPanel`) |
| `x509toolkit.generateKey` | Generate Key Pair (opens `KeyGenPanel`) |

---

## Testing

Unit tests live in `packages/core/src/test/` and use **Jest** with `ts-jest`. They test parsing logic directly without a VS Code extension host.

| Test file | What it covers |
|-----------|---------------|
| `certificateParser.test.ts` | `parseCertificate`, `parsePEMChain`, `parseCsr` |
| `certUtils.test.ts` | `bufToHex`, `parseDNString` |
| `derUtils.test.ts` | `derTLV`, `derOid`, `derInt`, `derStr` |
| `oidMaps.test.ts` | OID lookup tables |
| `p12Parser.test.ts` | `parseP12`, `generateCertificate`, `createSelfSignedP12` |
| `qcStatements.test.ts` | `parseQcStatements` |
| `caChainUtils.test.ts` | CA chain building utilities |

Webview component tests live in `packages/webview-ui/src/test/` and use **Vitest** + `@testing-library/svelte`.

---

## Important Conventions

- **Types are the single source of truth.** `packages/core/src/types/types.ts` defines all data shapes and message protocols. `packages/webview-ui/src/types.ts` re-exports from `@x509-toolkit/core` — no manual mirroring needed.
- Hex values throughout the codebase use colon-separated **uppercase** format (`AA:BB:CC`), produced by `certUtils.bufToHex`.
- Passphrase and generic input dialogs are rendered inside the webview (not native VS Code input boxes) to avoid focus loss; they use a `requestId` round-trip via `requestBridgeUtils.ts`.
- Each panel module enforces a single `WebviewPanel` instance via a module-level reference.
- The webview HTML is generated by `webviewPanelUtils.buildHtml()` which injects a CSP nonce and the correct `dist/webview` URIs. CSP `script-src` must include both `'nonce-${nonce}'` and `${webview.cspSource}` to allow Vite code-split chunks.
- When reusing an existing panel, `getOrCreatePanel()` calls `viewerQueue.reset()`; E2E tests must send a `ready` message after a command-triggered panel reset so queued extension→webview messages flush.
