<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { CertificateData } from '../types';

  export let cert: CertificateData;

  const dispatch = createEventDispatcher<{ copy: string; back: void }>();

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short',
    });
  }

  function formatHexBlocks(hexValue: string, bytesPerLine = 18): string[] {
    const bytes = hexValue.split(':').filter(Boolean);
    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += bytesPerLine) {
      lines.push(`         ${bytes.slice(i, i + bytesPerLine).join(':')}`);
    }
    return lines;
  }

  function formatIndentedHex(hexValue: string, indent: string, bytesPerLine = 15): string[] {
    const bytes = hexValue.split(':').filter(Boolean);
    const lines: string[] = [];
    for (let i = 0; i < bytes.length; i += bytesPerLine) {
      lines.push(`${indent}${bytes.slice(i, i + bytesPerLine).join(':')}`);
    }
    return lines;
  }

  function extensionLines(name: string, critical: boolean, value: string): string[] {
    const lines: string[] = [];
    const normalized = value.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const parts = normalized.split('\n').map(part => part.trimEnd()).filter(Boolean);

    if (parts.length === 0) {
      lines.push(`            ${name}${critical ? ': critical' : ':'}`);
      return lines;
    }

    lines.push(`            ${name}${critical ? ': critical' : ':'}`);
    for (const part of parts) {
      lines.push(`                ${part}`);
    }
    return lines;
  }

  function buildOpenSslLikeText(data: CertificateData): string {
    const lines: string[] = [];

    lines.push('Certificate:');
    lines.push('    Data:');
    lines.push(`        Version: ${data.version} (0x${Math.max(0, data.version - 1).toString(16)})`);
    lines.push('        Serial Number:');
    lines.push(`            ${data.serialNumber}`);
    lines.push(`        Signature Algorithm: ${data.signature.algorithm}`);
    lines.push(`        Issuer: ${data.issuer.raw}`);
    lines.push('        Validity');
    lines.push(`            Not Before: ${formatDate(data.validity.notBefore)}`);
    lines.push(`            Not After : ${formatDate(data.validity.notAfter)}`);
    lines.push(`        Subject: ${data.subject.raw}`);
    lines.push('        Subject Public Key Info:');
    lines.push(`            Public Key Algorithm: ${data.publicKey.algorithm}`);
    if (data.publicKey.keySize) {
      lines.push(`                Public-Key: (${data.publicKey.keySize} bit)`);
      lines.push('                pub:');
      lines.push(...formatIndentedHex(data.publicKey.spki, '                    '));
    }
    if (data.publicKey.namedCurve) {
      lines.push(`                ASN1 OID: ${data.publicKey.namedCurve}`);
    }

    if (data.extensions.length > 0) {
      lines.push('        X509v3 extensions:');
      for (const ext of data.extensions) {
        lines.push(...extensionLines(ext.name, ext.critical, ext.value));
      }
    }

    lines.push(`    Signature Algorithm: ${data.signature.algorithm}`);
    lines.push('    Signature Value:');
    lines.push(...formatHexBlocks(data.signature.value));
    lines.push('');
    lines.push('Toolkit Info:');
    lines.push(`    Certificate Authority: ${data.isCA ? 'TRUE' : 'FALSE'}`);
    lines.push(`    Self-Signed: ${data.isSelfSigned ? 'TRUE' : 'FALSE'}`);
    lines.push(`    Validity Status: ${data.validity.isExpired ? 'EXPIRED' : `VALID (${data.validity.daysRemaining} days remaining)`}`);
    lines.push('');
    lines.push('Fingerprint:');
    lines.push(`    SHA1: ${data.fingerprints.sha1}`);
    lines.push(`    SHA256: ${data.fingerprints.sha256}`);

    return lines.join('\n');
  }

  $: opensslLikeText = buildOpenSslLikeText(cert);
</script>

<div class="openssl-like" data-testid="openssl-like-view">
  <div class="openssl-toolbar">
    <!-- <button class="copy-btn" on:click={() => dispatch('back')} title="Back to standard certificate details">
      Back to Standard View
    </button> -->
    <button class="copy-btn" on:click={() => dispatch('copy', opensslLikeText)} title="Copy OpenSSL-like text">
      Copy Text
    </button>
  </div>

  <pre class="openssl-text">{opensslLikeText}</pre>

  <div class="openssl-raw-wrap">
    <div class="openssl-raw-title">Certificate PEM</div>
    <pre class="openssl-text">{cert.raw}</pre>
  </div>
</div>

<style>
  .openssl-like {
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }

  .openssl-toolbar {
    display: flex;
    justify-content: flex-end;
    gap: 0.4rem;
    flex-wrap: wrap;
    padding: 0.15rem 0.1rem 0;
  }

  .openssl-text {
    margin: 0;
    padding: 0.8rem;
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.74rem;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--vscode-editor-foreground);
    background: var(--vscode-input-background, rgba(0,0,0,0.18));
    border-radius: 4px;
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.09));
  }

  .openssl-raw-wrap {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .openssl-raw-title {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--vscode-descriptionForeground, #888);
    font-weight: 600;
    padding: 0 0.1rem;
  }
</style>
