<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { CertificateData, DistinguishedName } from '../types';
  import SectionCard from './SectionCard.svelte';
  import FieldRow from './FieldRow.svelte';
  import ValidityIndicator from './ValidityIndicator.svelte';
  import ExtensionsList from './ExtensionsList.svelte';
  import HexValue from './HexValue.svelte';
  import Fingerprints from './Fingerprints.svelte';

  export let cert: CertificateData;
  export let loadingUrls: Set<string> = new Set();
  export let topOffset = 0;

  const dispatch = createEventDispatcher<{ copy: string; loadCaIssuer: string; export: { pem: string; suggestedName: string } }>();

  function copy(value: string): void {
    dispatch('copy', value);
  }

  function exportCert(): void {
    const cn = cert.subject.commonName ?? cert.issuer.commonName ?? 'certificate';
    const safeName = cn.replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 64);
    dispatch('export', { pem: cert.raw, suggestedName: `${safeName}.pem` });
  }

  function formatDate(iso: string): string {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short',
    });
  }

  function dnFields(dn: DistinguishedName): [string, string][] {
    const rows: [string, string][] = [];
    if (dn.commonName)         rows.push(['Common Name',         dn.commonName]);
    if (dn.organization)       rows.push(['Organization',        dn.organization]);
    if (dn.organizationalUnit) rows.push(['Org. Unit',           dn.organizationalUnit]);
    if (dn.country)            rows.push(['Country',             dn.country]);
    if (dn.state)              rows.push(['State / Province',    dn.state]);
    if (dn.locality)           rows.push(['Locality',            dn.locality]);
    if (dn.email)              rows.push(['Email',               dn.email]);
    if (dn.domainComponent)    rows.push(['Domain Component',    dn.domainComponent]);
    if (dn.userId)             rows.push(['User ID',             dn.userId]);
    return rows;
  }

  function validityStatus(v: { isExpired: boolean; daysRemaining: number }): string {
    if (v.isExpired) return `Expired ${Math.abs(v.daysRemaining)} day(s) ago`;
    if (v.daysRemaining <= 30) return `Expires in ${v.daysRemaining} day(s)`;
    return `Valid — ${v.daysRemaining} days remaining`;
  }

  $: subjectRows = dnFields(cert.subject);
  $: issuerRows  = dnFields(cert.issuer);

  // Derive DER bytes from PEM for the hex dump
  $: derHex = (() => {
    try {
      const b64 = cert.raw
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s+/g, '');
      const binary = atob(b64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes;
    } catch { return new Uint8Array(0); }
  })();

  $: hexDump = (() => {
    const lines: string[] = [];
    const COLS = 16;
    for (let off = 0; off < derHex.length; off += COLS) {
      const slice = derHex.slice(off, off + COLS);
      const hex   = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(slice).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
      const pad   = '   '.repeat(COLS - slice.length);
      lines.push(`${off.toString(16).padStart(8, '0')}  ${hex}${pad}  |${ascii}|`);
    }
    return lines.join('\n');
  })();

  $: hexDumpText = hexDump;
</script>

<div class="cert-view">

  <!-- ── Sticky top: header + summary bar ── -->
  <div class="sticky-top" style="top: {topOffset}px">

  <!-- ── Hero header ── -->
  <header class="cert-header">
    <div class="cert-header-left">
      <div class="cert-icon">🔏</div>
      <div class="cert-title">
        <h1 class="cert-cn">{cert.subject.commonName ?? cert.subject.raw}</h1>
        <div class="cert-badges">
          <span class="meta-badge version">v{cert.version}</span>
          {#if cert.isCA}
            <span class="meta-badge ca">Certificate Authority</span>
          {:else}
            <span class="meta-badge ee">End-Entity</span>
          {/if}
          {#if cert.isSelfSigned}
            <span class="meta-badge self">Self-Signed</span>
          {/if}
        </div>
      </div>
    </div>
    <div class="cert-header-right">
      <ValidityIndicator validity={cert.validity} />
      <button class="export-btn" title="Export certificate" on:click={exportCert}>
        ⤓ Export
      </button>
    </div>
  </header>

  <!-- ── Quick-look summary bar ── -->
  <div class="summary-bar">
    <div class="sum-item">
      <span class="sum-lbl">Algorithm</span>
      <span class="sum-val">{cert.publicKey.algorithm}</span>
    </div>
    {#if cert.publicKey.keySize}
      <div class="sum-item">
        <span class="sum-lbl">Key Size</span>
        <span class="sum-val">{cert.publicKey.keySize} bits</span>
      </div>
    {/if}
    {#if cert.publicKey.namedCurve}
      <div class="sum-item">
        <span class="sum-lbl">Curve</span>
        <span class="sum-val">{cert.publicKey.namedCurve}</span>
      </div>
    {/if}
    {#if cert.subject.organization}
      <div class="sum-item">
        <span class="sum-lbl">Organization</span>
        <span class="sum-val">{cert.subject.organization}</span>
      </div>
    {/if}
    {#if cert.subject.country}
      <div class="sum-item">
        <span class="sum-lbl">Country</span>
        <span class="sum-val">{cert.subject.country}</span>
      </div>
    {/if}
    <div class="sum-item">
      <span class="sum-lbl">Extensions</span>
      <span class="sum-val">
        {cert.extensions.length}
        {cert.extensions.filter(e => e.critical).length > 0
          ? `(${cert.extensions.filter(e => e.critical).length} critical)`
          : ''}
      </span>
    </div>
  </div>

  </div><!-- /.sticky-top -->

  <!-- ── Sections ── -->
  <div class="sections">

    <!-- Subject -->
    <SectionCard title="Subject" icon="👤">
      {#each subjectRows as [label, value]}
        <FieldRow {label} {value} copyable on:copy={() => copy(value)} />
      {/each}
      <FieldRow label="Full DN" value={cert.subject.raw} copyable mono on:copy={() => copy(cert.subject.raw)} />
    </SectionCard>

    <!-- Issuer -->
    <SectionCard title="Issuer" icon="🏛️">
      {#each issuerRows as [label, value]}
        <FieldRow {label} {value} copyable on:copy={() => copy(value)} />
      {/each}
      <FieldRow label="Full DN" value={cert.issuer.raw} copyable mono on:copy={() => copy(cert.issuer.raw)} />
    </SectionCard>

    <!-- Validity -->
    <SectionCard title="Validity" icon="📅">
      <FieldRow label="Not Before"    value={formatDate(cert.validity.notBefore)} copyable on:copy={() => copy(cert.validity.notBefore)} />
      <FieldRow label="Not After"     value={formatDate(cert.validity.notAfter)}  copyable on:copy={() => copy(cert.validity.notAfter)} />
      <FieldRow label="Status"        value={validityStatus(cert.validity)} />
      <FieldRow label="Serial Number" value={cert.serialNumber} copyable mono on:copy={() => copy(cert.serialNumber)} />
    </SectionCard>

    <!-- Public Key -->
    <SectionCard title="Public Key" icon="🔑">
      <FieldRow label="Algorithm" value={cert.publicKey.algorithm} />
      {#if cert.publicKey.keySize}
        <FieldRow label="Key Size"    value="{cert.publicKey.keySize} bits" />
      {/if}
      {#if cert.publicKey.namedCurve}
        <FieldRow label="Named Curve" value={cert.publicKey.namedCurve} />
      {/if}
      <div class="field-hex">
        <span class="fh-label">SPKI (Public Key)</span>
        <HexValue value={cert.publicKey.spki} on:copy={() => copy(cert.publicKey.spki)} />
      </div>
    </SectionCard>

    <!-- Signature -->
    <SectionCard title="Signature" icon="✍️">
      <FieldRow label="Algorithm" value={cert.signature.algorithm} />
      <div class="field-hex">
        <span class="fh-label">Signature Value</span>
        <HexValue value={cert.signature.value} on:copy={() => copy(cert.signature.value)} />
      </div>
    </SectionCard>

    <!-- Extensions -->
    {#if cert.extensions.length > 0}
      <SectionCard title="Extensions ({cert.extensions.length})" icon="🧩">
        <ExtensionsList
          extensions={cert.extensions}
          {loadingUrls}
          on:copy={(e) => copy(e.detail)}
          on:loadCaIssuer={(e) => dispatch('loadCaIssuer', e.detail)}
        />
      </SectionCard>
    {/if}

    <!-- Fingerprints -->
    <SectionCard title="Fingerprints" icon="🔎">
      <Fingerprints fingerprints={cert.fingerprints} on:copy={(e) => copy(e.detail)} />
    </SectionCard>

    <!-- Raw PEM -->
    <SectionCard title="Raw Certificate (PEM)" icon="📄" collapsed={true}>
      <div class="raw-pem-wrap">
        <button class="copy-btn raw-copy-btn" on:click={() => copy(cert.raw)} title="Copy PEM">
          ⧉ Copy PEM
        </button>
        <pre class="raw-pem">{cert.raw}</pre>
      </div>
    </SectionCard>

    <!-- Binary DER hex dump -->
    <SectionCard title="Binary Data (DER, {derHex.length} bytes)" icon="🗂️" collapsed={true}>
      <div class="raw-pem-wrap">
        <button class="copy-btn raw-copy-btn" on:click={() => copy(hexDumpText)} title="Copy hex dump">
          ⧉ Copy
        </button>
        <pre class="hex-dump">{hexDump}</pre>
      </div>
    </SectionCard>

  </div>
</div>

<style>
  .cert-view {
    display: flex;
    flex-direction: column;
  }

  /* ── Sticky header wrapper ── */
  .sticky-top {
    position: sticky;
    top: 0;
    z-index: 10;
    background: var(--vscode-sideBar-background, #181825);
  }

  /* ── Header ── */
  .cert-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    padding: 1.1rem 1.4rem 0.9rem;
    background: var(--vscode-sideBar-background, #181825);
    border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.1));
    flex-wrap: wrap;
  }

  .cert-header-right {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    flex-shrink: 0;
  }

  .export-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.28rem 0.7rem;
    background: var(--vscode-button-secondaryBackground, rgba(255,255,255,0.07));
    color: var(--vscode-button-secondaryForeground, var(--vscode-editor-foreground));
    border: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.15));
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.75rem;
    font-family: var(--vscode-font-family);
    white-space: nowrap;
    transition: background 0.12s, border-color 0.12s;
  }
  .export-btn:hover {
    background: var(--vscode-button-secondaryHoverBackground, rgba(255,255,255,0.12));
    border-color: var(--vscode-focusBorder, rgba(255,255,255,0.3));
  }

  .cert-header-left {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    min-width: 0;
  }

  .cert-icon { font-size: 1.9rem; line-height: 1; flex-shrink: 0; margin-top: 2px; }

  .cert-title { min-width: 0; }

  .cert-cn {
    margin: 0 0 0.3rem;
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--vscode-editor-foreground);
    word-break: break-all;
  }

  .cert-badges { display: flex; flex-wrap: wrap; gap: 0.3rem; }

  .meta-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.67rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .meta-badge.version {
    background: rgba(255,255,255,0.06);
    color: var(--vscode-descriptionForeground, #888);
    border: 1px solid rgba(255,255,255,0.09);
  }
  .meta-badge.ca {
    background: rgba(148,130,209,0.18);
    color: #b4a7d6;
    border: 1px solid rgba(148,130,209,0.35);
  }
  .meta-badge.ee {
    background: rgba(137,220,235,0.12);
    color: #89dceb;
    border: 1px solid rgba(137,220,235,0.28);
  }
  .meta-badge.self {
    background: rgba(250,179,135,0.12);
    color: #fab387;
    border: 1px solid rgba(250,179,135,0.28);
  }

  /* ── Summary bar ── */
  .summary-bar {
    display: flex;
    flex-wrap: wrap;
    background: var(--vscode-sideBar-background, #181825);
    border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.07));
  }

  .sum-item {
    display: flex;
    flex-direction: column;
    padding: 0.55rem 1.1rem;
    border-right: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.07));
    min-width: 90px;
  }

  .sum-lbl {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--vscode-descriptionForeground, #888);
    font-weight: 600;
  }

  .sum-val {
    font-size: 0.82rem;
    color: var(--vscode-editor-foreground);
    font-weight: 500;
  }

  /* ── Sections ── */
  .sections {
    padding: 0.9rem 1.1rem;
    display: flex;
    flex-direction: column;
    gap: 0.55rem;
  }

  /* ── Hex field label ── */
  .field-hex {
    padding: 0.3rem 0.7rem 0.55rem;
    display: flex;
    flex-direction: column;
    gap: 0.28rem;
  }

  .fh-label {
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--vscode-descriptionForeground, #888);
    font-weight: 600;
  }

  /* ── Raw PEM ── */
  .raw-pem-wrap { position: relative; }

  .raw-copy-btn {
    position: absolute;
    top: 0.5rem;
    right: 0.5rem;
    z-index: 1;
  }

  .raw-pem {
    margin: 0;
    padding: 0.7rem;
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.7rem;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--vscode-editor-foreground);
    background: var(--vscode-input-background, rgba(0,0,0,0.18));
    border-radius: 4px;
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.09));
    overflow-x: auto;
  }

  .hex-dump {
    margin: 0;
    padding: 0.7rem;
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.69rem;
    white-space: pre;
    word-break: normal;
    color: var(--vscode-editor-foreground);
    background: var(--vscode-input-background, rgba(0,0,0,0.18));
    border-radius: 4px;
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.09));
    overflow-x: auto;
    line-height: 1.6;
  }

  /* ── Global copy-button style ── */
  :global(.copy-btn) {
    display: inline-flex;
    align-items: center;
    gap: 0.2rem;
    padding: 2px 8px;
    background: var(--vscode-button-secondaryBackground, rgba(255,255,255,0.06));
    color: var(--vscode-button-secondaryForeground, var(--vscode-editor-foreground));
    border: 1px solid var(--vscode-button-border, rgba(255,255,255,0.1));
    border-radius: 4px;
    font-size: 0.7rem;
    font-family: var(--vscode-font-family);
    cursor: pointer;
    transition: background 0.13s;
    white-space: nowrap;
  }

  :global(.copy-btn:hover) {
    background: var(--vscode-button-secondaryHoverBackground, rgba(255,255,255,0.11));
  }
</style>
