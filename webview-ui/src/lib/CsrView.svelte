<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { CsrData, WebviewToExtMsg } from '../types';
  import SectionCard from './SectionCard.svelte';
  import FieldRow from './FieldRow.svelte';
  import ExtensionsList from './ExtensionsList.svelte';

  export let csr: CsrData;

  const dispatch = createEventDispatcher<{ copy: string; signCsr: void; saveCsr: void; saveKey: void }>();

  function copyText(text: string): void {
    dispatch('copy', text);
  }

  function handleSignCsr(): void {
    dispatch('signCsr');
  }

  function saveCsr(): void { dispatch('saveCsr'); }
  function saveKey(): void { dispatch('saveKey'); }

  $: subject = csr.subject;
  $: pk = csr.publicKey;
</script>

<div class="csr-view">
  <!-- ── Header ──────────────────────────────────────────────────────────── -->
  <div class="csr-header">
    <div class="csr-header-info">
      <span class="csr-badge">CSR</span>
      <div>
        <div class="csr-cn">{subject.commonName ?? subject.raw}</div>
        <div class="csr-subtitle">Certificate Signing Request — not yet signed</div>
      </div>
    </div>
    <button class="btn-sign" on:click={handleSignCsr}>
      ✍ Sign this CSR…
    </button>
  </div>

  <!-- ── Subject ─────────────────────────────────────────────────────────── -->
  <SectionCard title="Subject">
    {#if subject.commonName}
      <FieldRow label="Common Name" value={subject.commonName} on:copy={e => copyText(e.detail)} />
    {/if}
    {#if subject.organization}
      <FieldRow label="Organization" value={subject.organization} on:copy={e => copyText(e.detail)} />
    {/if}
    {#if subject.organizationalUnit}
      <FieldRow label="Org. Unit" value={subject.organizationalUnit} on:copy={e => copyText(e.detail)} />
    {/if}
    {#if subject.country}
      <FieldRow label="Country" value={subject.country} on:copy={e => copyText(e.detail)} />
    {/if}
    {#if subject.state}
      <FieldRow label="State" value={subject.state} on:copy={e => copyText(e.detail)} />
    {/if}
    {#if subject.locality}
      <FieldRow label="Locality" value={subject.locality} on:copy={e => copyText(e.detail)} />
    {/if}
    {#if subject.email}
      <FieldRow label="Email" value={subject.email} on:copy={e => copyText(e.detail)} />
    {/if}
    <FieldRow label="DN (raw)" value={subject.raw} on:copy={e => copyText(e.detail)} mono />
  </SectionCard>

  <!-- ── Public Key ──────────────────────────────────────────────────────── -->
  <SectionCard title="Public Key">
    <FieldRow label="Algorithm" value={pk.algorithm} />
    {#if pk.keySize}
      <FieldRow label="Key Size" value="{pk.keySize} bits" />
    {/if}
    {#if pk.namedCurve}
      <FieldRow label="Curve" value={pk.namedCurve} />
    {/if}
    <FieldRow label="Signature Algorithm" value={csr.signatureAlgorithm} />
  </SectionCard>

  <!-- ── Requested Extensions ────────────────────────────────────────────── -->
  {#if csr.extensions.length > 0}
    <SectionCard title="Requested Extensions">
      <ExtensionsList extensions={csr.extensions} on:copy={e => copyText(e.detail)} />
    </SectionCard>
  {/if}

  <!-- ── Raw PEM ─────────────────────────────────────────────────────────── -->
  <SectionCard title="Raw PEM">
    <div class="pem-actions">
      <button class="btn-copy" on:click={() => copyText(csr.raw)}>Copy PEM</button>
      <button class="btn-copy" on:click={saveCsr}>Save CSR…</button>
    </div>
    <pre class="pem-block">{csr.raw}</pre>
  </SectionCard>

  <!-- ── Private Key ────────────────────────────────────────────────────── -->
  {#if csr.privateKeyDescription}
    <SectionCard title="Private Key">
      <div class="key-section">
        <div class="key-row">
          <FieldRow label="Key" value={csr.privateKeyDescription} />
        </div>
        <div class="key-actions">
          <button class="btn-sign" on:click={saveKey}>Save Private Key…</button>
        </div>
        <p class="key-warning">⚠ The private key is held in memory. Save it now — it will be lost when the panel is closed or a new file is opened.</p>
      </div>
    </SectionCard>
  {/if}
</div>

<style>
  .csr-view {
    padding: 16px;
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
    max-width: 900px;
  }

  /* ── Header */
  .csr-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 16px;
    padding: 14px 16px;
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 12%, transparent);
    border: 1px solid var(--vscode-editorWarning-foreground, #cca700);
    border-radius: 4px;
  }
  .csr-header-info { display: flex; align-items: center; gap: 12px; }
  .csr-badge {
    display: inline-block;
    padding: 3px 8px;
    background: var(--vscode-editorWarning-foreground, #cca700);
    color: var(--vscode-editor-background, #1e1e1e);
    font-size: 0.75em;
    font-weight: 700;
    border-radius: 3px;
    letter-spacing: 0.05em;
    flex-shrink: 0;
  }
  .csr-cn {
    font-weight: 600;
    font-size: 1.05em;
    color: var(--vscode-foreground);
  }
  .csr-subtitle {
    font-size: 0.82em;
    color: var(--vscode-descriptionForeground);
    margin-top: 2px;
  }

  /* ── Sign button */
  .btn-sign {
    padding: 7px 16px;
    background: var(--vscode-button-background, #0e639c);
    color: var(--vscode-button-foreground, #fff);
    border: none;
    border-radius: 2px;
    font-family: inherit;
    font-size: 0.9em;
    cursor: pointer;
    white-space: nowrap;
    flex-shrink: 0;
  }
  .btn-sign:hover { background: var(--vscode-button-hoverBackground, #1177bb); }

  /* ── PEM block */
  .pem-actions { margin-bottom: 8px; }
  .btn-copy {
    padding: 4px 10px;
    background: var(--vscode-button-secondaryBackground, #3a3d41);
    color: var(--vscode-button-secondaryForeground, #ccc);
    border: none;
    border-radius: 2px;
    font-family: inherit;
    font-size: 0.82em;
    cursor: pointer;
  }
  .btn-copy:hover { background: var(--vscode-button-secondaryHoverBackground, #45494e); }
  .pem-block {
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.78em;
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, #555);
    border-radius: 2px;
    padding: 10px 12px;
    margin: 0;
    white-space: pre;
    overflow-x: auto;
    word-break: break-all;
  }

  /* ── Private key section */
  .key-section { display: flex; flex-direction: column; gap: 10px; }
  .key-row { margin-bottom: 0; }
  .key-actions { display: flex; gap: 8px; }
  .key-warning {
    margin: 0;
    padding: 8px 12px;
    font-size: 0.85em;
    color: var(--vscode-editorWarning-foreground, #cca700);
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 10%, transparent);
    border-radius: 3px;
  }
</style>
