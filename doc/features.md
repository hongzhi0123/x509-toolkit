Explore current extension features

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/extension.ts)

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/types/types.ts)

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/certificateParser.ts#1-1), lines 1 to 150

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/p12Parser.ts#1-1), lines 1 to 150

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/panels/createCertPanel.ts#1-1), lines 1 to 150

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/p12Parser.ts#150-150), lines 150 to 500

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/panels/createCertPanel.ts#150-150), lines 150 to 325

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/panels/panelManager.ts#1-1), lines 1 to 200

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/commands/openFile.ts)

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/certificateParser.ts#100-100), lines 100 to 100

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/webview-ui/src/App.svelte#1-1), lines 1 to 200

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/webview-ui/src/lib/CreateCertPanel.svelte#1-1), lines 1 to 100

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/webview-ui/src/lib/CsrView.svelte#1-1), lines 1 to 100

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/certificateParser.ts#100-100), lines 100 to 300

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/commands/showFromSelection.ts)

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/commands/openFromExplorer.ts)

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/utils/handleX509Input.ts)

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/panels/panelManager.ts#200-200), lines 200 to 400

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/panels/panelManager.ts#400-400), lines 400 to 600

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/p12Parser.ts#300-300), lines 300 to 750

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/p12Parser.ts#819-819), lines 819 to 819

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/certificateParser.ts#300-300), lines 300 to 377

Searched for regex `export.*async.*function.*signCsr`, 1 result

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/webview-ui/src/lib/CertificateView.svelte#1-1), lines 1 to 150

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/src/parsers/p12Parser.ts#760-760), lines 760 to 819

Read [](file:///d%3A/Dev/ai/x509-viewer/x509-toolkit/webview-ui/src/lib/CreateCertPanel.svelte#100-100), lines 100 to 200

Read [](file:///c%3A/Users/aczm/AppData/Roaming/Code/User/workspaceStorage/fee48164193460491d818707fcf815be/GitHub.copilot-chat/chat-session-resources/ceef76b7-0ba9-4922-8af9-9765887df303/toolu_bdrk_01ADZ6cV12EwciikjujCqPiv__vscode-1779613155245/content.txt#1-1), lines 1 to 150

Now I have a clear picture of what's already built. Let me think through the most valuable OpenSSL equivalents to recommend. 

Created memory file [](file:///c%3A/Users/aczm/AppData/Roaming/Code/User/workspaceStorage/fee48164193460491d818707fcf815be/GitHub.copilot-chat/memory-tool/memories/Y2VlZjc2YjctMGJhOS00OTIyLThhZjktOTc2NTg4N2RmMzAz/plan.md)

Here's my analysis of the most valuable OpenSSL features to add, grouped by impact:

---

## High-Impact: "I reach for openssl every day for this"

### 1. TLS Server Certificate Inspector (`openssl s_client -connect host:port -showcerts`)
The single most commonly used openssl command for developers. Enter a hostname (and optional port), the extension connects, pulls the full live certificate chain, and displays it exactly like a file-based cert — including chain order, expiry, SANs, etc.
- Covers: debugging TLS misconfigurations, verifying deployed certificates, checking SNI, checking cert pinning

### 2. Format Conversion Hub (`openssl x509 -inform DER -outform PEM`, `openssl pkcs12 -export`, `openssl pkcs12 -nokeys -clcerts`)
People constantly need:
- Extract cert(s) and/or private key from a P12 → separate PEM files
- Merge a PEM cert + PEM key → P12
- PEM ↔ DER for both certs and keys
- Bundle a cert chain into one multi-cert PEM

This is currently partially there but the UX doesn't expose it as a first-class conversion operation.

### 3. OCSP Revocation Check (`openssl ocsp`)
The OCSP URL is already parsed from AIA extensions. The extension could fire an OCSP request automatically and show a **revoked / good / unknown** badge inline in the cert view. This is high-visibility because it makes a passive display interactive.

### 4. Certificate Chain Verification (`openssl verify -CAfile root.pem chain.pem`)
Given a leaf certificate (or a chain), verify the cryptographic path to a trust anchor. The user provides (or AIA-downloads) intermediates and a root CA, and the extension confirms: chain is valid / broken at which hop / signature mismatch. Huge for debugging "untrusted certificate" errors.

---

## Medium-Impact: Replaces frequent but less daily openssl use

### 5. Standalone Private/Public Key Viewer (`openssl rsa -text`, `openssl ec -text`, `openssl pkey -text`)
Currently keys are only shown in the context of a certificate. A standalone key viewer for PEM/DER key files would show: algorithm, key size / curve, modulus+exponent (RSA), key ID, and whether the key is encrypted. Plus key format conversion (PKCS#1 ↔ PKCS#8, PEM ↔ DER, encrypted ↔ unencrypted).

### 6. CRL Viewer (`openssl crl -text`)
Parse and display Certificate Revocation Lists (`.crl` files, PEM or DER). Show issuer, validity dates, next update, and the list of revoked serial numbers. Combined with the OCSP feature, gives full revocation coverage.

### 7. PKCS#7 / CMS Bundle Viewer (`openssl pkcs7 -print_certs`)
Parse `.p7b` / `.p7c` files (common in Windows environments and S/MIME) and display all embedded certificates. These files are pure certificate bundles with no private key, very common in enterprise PKI.

### 8. Certificate Linter / Policy Checker
Given an open certificate, run a set of checks (beyond pure display) and highlight problems:
- Expired or expiring within N days
- Weak key (RSA < 2048, SHA-1 signature)
- Missing SANs on a TLS cert (CN-only, deprecated since RFC 2818)
- Key usage doesn't match EKU
- Self-signed used where CA-signed expected
This replaces `openssl verify` + manual inspection.

---

## Lower-Impact: Nice to have

### 9. Standalone Key Generation (`openssl genpkey`, `openssl genrsa`, `openssl ecparam -genkey`)
Generate a raw key pair without creating a certificate — useful for generating keys to be submitted in a CSR workflow managed externally.

### 10. Certificate Diff / Compare
Select two certificates and compare fields side-by-side — useful when rolling certificates (old vs. new) to confirm SANs, key usage, validity are as expected.

---

## Recommended Priority Order

| # | Feature | Replaces | Effort |
|---|---------|----------|--------|
| 1 | **TLS Server Inspector** | `s_client` | Medium |
| 2 | **Format Conversion Hub** | `pkcs12 -export/-nokeys`, `x509 -outform` | Low |
| 3 | **OCSP Revocation Check** | `openssl ocsp` | Low (URL already parsed) |
| 4 | **Chain Verification** | `openssl verify` | Medium |
| 5 | **Standalone Key Viewer** | `rsa/ec/pkey -text` | Low |
| 6 | **CRL Viewer** | `openssl crl -text` | Low |
| 7 | **PKCS#7 Viewer** | `openssl pkcs7` | Low |
| 8 | **Certificate Linter** | manual inspection | Medium |

---

**What I'd suggest starting with:** TLS Server Inspector (#1) + Format Conversion Hub (#2) + OCSP inline check (#3). These three alone cover probably 70% of day-to-day openssl use without requiring a terminal at all.

Want me to flesh out any of these into a detailed implementation plan?