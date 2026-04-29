# X.509 Certificate Viewer

A VS Code extension for visually inspecting X.509 certificates with a rich Svelte-powered webview UI.

## Features

- **Show from Selection** — Select PEM certificate text in any editor, right-click → *X.509 Viewer: Show Certificate from Selection* (or use the Command Palette).
- **Open File** — Open a PEM (`.pem`, `.crt`, `.cer`) or DER binary (`.der`, `.cer`) file via the Command Palette.
- **Chain support** — When a PEM file contains a certificate chain, each certificate is shown as a tab.
- **Structured overview** — Subject, Issuer, Validity, Public Key, Signature, Extensions, Fingerprints – all in collapsible cards.
- **Deep details** — Every extension is expandable; long hex values are truncated with a *Show all* option.
- **Copy to clipboard** — Every field and hex value has a copy button.
- **VS Code theme integration** — Light and dark themes supported via CSS variables.

## Commands

| Command | Description |
|---|---|
| `X.509 Viewer: Show Certificate from Selection` | Parse PEM from the active editor selection |
| `X.509 Viewer: Open Certificate File` | Open a PEM or DER certificate file from disk |

The *Show from Selection* command is also available in the **right-click context menu** when text is selected.

## Tech Stack

- **Extension host**: TypeScript compiled with webpack
- **Certificate parsing**: [`@peculiar/x509`](https://github.com/PeculiarVentures/x509) + [`@peculiar/webcrypto`](https://github.com/PeculiarVentures/webcrypto)
- **Webview UI**: [Svelte 4](https://svelte.dev/) + [Vite](https://vitejs.dev/)

## Development

```bash
# First-time setup: install all dependencies and do a full build
cd C:\Users\aczm\source\x509-viewer
npm install
npm run build

# Watch mode for iterative development (run in separate terminals):
npm run watch:ext        # webpack watch – rebuilds extension on src/ changes
npm run watch:webview    # vite dev build – rebuilds webview on webview-ui/src/ changes
```

Press **F5** in VS Code (with this folder open) to launch the Extension Development Host.

## Supported Formats

| Format | Extensions | Notes |
|---|---|---|
| PEM (text) | `.pem`, `.crt`, `.cer` | Handles single cert or full chain |
| DER (binary) | `.der`, `.cer` | Single certificate |
| Editor selection | — | PEM text selected in any file/editor |
