<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { CsrData } from '../types';
  import SectionCard from './SectionCard.svelte';
  import FieldRow from './FieldRow.svelte';
  import ExtensionsList from './ExtensionsList.svelte';

  export let csr: CsrData;

  const dispatch = createEventDispatcher<{ copy: string; signCsr: void; saveCsr: void; saveKey: void; saveBoth: void }>();

  function copyText(text: string): void {
    dispatch('copy', text);
  }

  function handleSignCsr(): void {
    dispatch('signCsr');
  }

  function saveCsr(): void { dispatch('saveCsr'); }
  function saveKey(): void { dispatch('saveKey'); }
  function saveBoth(): void { dispatch('saveBoth'); }

  $: subject = csr.subject;
  $: pk = csr.publicKey;
</script>

<div class="csr-view">

  <!-- ── Sticky top: header + summary bar ── -->
  <div class="sticky-top">

    <!-- ── Hero header ── -->
    <header class="csr-header">
      <div class="csr-header-left">
        <div class="csr-icon">✍️</div>
        <div class="csr-title">
          <h1 class="csr-cn">{subject.commonName ?? subject.raw}</h1>
          <div class="csr-badges">
            <span class="meta-badge csr-tag">CSR</span>
            <span class="meta-badge pending">Not Yet Signed</span>
          </div>
        </div>
      </div>
      <div class="csr-header-right">
        <button class="export-btn sign-btn" on:click={handleSignCsr}>
          ✍ Sign this CSR…
        </button>
      </div>
    </header>

    <!-- ── Summary bar ── -->
    <div class="summary-bar">
      <div class="sum-item">
        <span class="sum-lbl">Algorithm</span>
        <span class="sum-val">{pk.algorithm}</span>
      </div>
      {#if pk.keySize}
        <div class="sum-item">
          <span class="sum-lbl">Key Size</span>
          <span class="sum-val">{pk.keySize} bits</span>
        </div>
      {/if}
      {#if pk.namedCurve}
        <div class="sum-item">
          <span class="sum-lbl">Curve</span>
          <span class="sum-val">{pk.namedCurve}</span>
        </div>
      {/if}
      {#if subject.organization}
        <div class="sum-item">
          <span class="sum-lbl">Organization</span>
          <span class="sum-val">{subject.organization}</span>
        </div>
      {/if}
      {#if subject.country}
        <div class="sum-item">
          <span class="sum-lbl">Country</span>
          <span class="sum-val">{subject.country}</span>
        </div>
      {/if}
      {#if csr.extensions.length > 0}
        <div class="sum-item">
          <span class="sum-lbl">Requested Ext.</span>
          <span class="sum-val">{csr.extensions.length}</span>
        </div>
      {/if}
    </div>

    <!-- ── Unsaved banner (only when a private key is in memory) ── -->
    {#if csr.privateKeyDescription}
      <div class="unsaved-banner">
        <span class="unsaved-text">⚠ Not saved yet — the CSR and its private key are held in memory and will be lost when this panel closes.</span>
        <button class="export-btn sign-btn" on:click={saveBoth}>⤓ Save Both…</button>
      </div>
    {/if}

  </div><!-- /.sticky-top -->

  <!-- ── Sections ── -->
  <div class="sections">

    <!-- Subject -->
    <SectionCard title="Subject" icon="📋">
      {#if subject.commonName}
        <FieldRow label="Common Name" value={subject.commonName} copyable on:copy={() => copyText(subject.commonName ?? '')} />
      {/if}
      {#if subject.organization}
        <FieldRow label="Organization" value={subject.organization} copyable on:copy={() => copyText(subject.organization ?? '')} />
      {/if}
      {#if subject.organizationalUnit}
        <FieldRow label="Org. Unit" value={subject.organizationalUnit} copyable on:copy={() => copyText(subject.organizationalUnit ?? '')} />
      {/if}
      {#if subject.country}
        <FieldRow label="Country" value={subject.country} copyable on:copy={() => copyText(subject.country ?? '')} />
      {/if}
      {#if subject.state}
        <FieldRow label="State" value={subject.state} copyable on:copy={() => copyText(subject.state ?? '')} />
      {/if}
      {#if subject.locality}
        <FieldRow label="Locality" value={subject.locality} copyable on:copy={() => copyText(subject.locality ?? '')} />
      {/if}
      {#if subject.email}
        <FieldRow label="Email" value={subject.email} copyable on:copy={() => copyText(subject.email ?? '')} />
      {/if}
      <FieldRow label="DN (raw)" value={subject.raw} copyable mono on:copy={() => copyText(subject.raw)} />
    </SectionCard>

    <!-- Public Key -->
    <SectionCard title="Public Key" icon="🔑">
      <FieldRow label="Algorithm" value={pk.algorithm} />
      {#if pk.keySize}
        <FieldRow label="Key Size" value="{pk.keySize} bits" />
      {/if}
      {#if pk.namedCurve}
        <FieldRow label="Curve" value={pk.namedCurve} />
      {/if}
      <FieldRow label="Signature Algorithm" value={csr.signatureAlgorithm} />
    </SectionCard>

    <!-- Requested Extensions -->
    {#if csr.extensions.length > 0}
      <SectionCard title="Requested Extensions ({csr.extensions.length})" icon="🧩">
        <ExtensionsList extensions={csr.extensions} on:copy={e => copyText(e.detail)} />
      </SectionCard>
    {/if}

    <!-- Raw CSR PEM (collapsed by default) -->
    <SectionCard title="Raw CSR (PEM)" icon="📄" collapsed={true}>
      <div class="raw-pem-wrap">
        <div class="pem-toolbar">
          <button class="copy-btn" on:click={() => copyText(csr.raw)} title="Copy PEM">⧉ Copy PEM</button>
          <button class="copy-btn" on:click={saveCsr} title="Save CSR only">⤓ Save CSR only…</button>
        </div>
        <pre class="raw-pem">{csr.raw}</pre>
      </div>
    </SectionCard>

    <!-- ── Private Key (separate artifact) ── -->
    {#if csr.privateKeyDescription}
      <div class="key-divider">
        <span class="key-divider-label">🗝️ Private Key</span>
      </div>
      <SectionCard title="Private Key" icon="🗝️" variant="key">
        <FieldRow label="Key" value={csr.privateKeyDescription} />
        <p class="key-note">This is a separate artifact — it is never transmitted in the CSR. Use <em>Save Both…</em> above to save it.</p>
      </SectionCard>
    {/if}

  </div><!-- /.sections -->

</div>

<style>
  .csr-view {
    display: flex;
    flex-direction: column;
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
  }

  /* ── Sticky header wrapper ── */
  .sticky-top {
    position: sticky;
    top: 0;
    z-index: 10;
    background: var(--vscode-sideBar-background, #181825);
  }

  /* ── Hero header ── */
  .csr-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 1rem;
    padding: 1.1rem 1.4rem 0.9rem;
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 8%, var(--vscode-sideBar-background, #181825));
    border-bottom: 1px solid color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 30%, transparent);
    flex-wrap: wrap;
  }

  .csr-header-left {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    min-width: 0;
  }

  .csr-icon { font-size: 1.9rem; line-height: 1; flex-shrink: 0; margin-top: 2px; }

  .csr-title { min-width: 0; }

  .csr-cn {
    margin: 0 0 0.3rem;
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--vscode-editor-foreground);
    word-break: break-all;
  }

  .csr-badges { display: flex; flex-wrap: wrap; gap: 0.3rem; }

  .meta-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.67rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .meta-badge.csr-tag {
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 25%, transparent);
    color: var(--vscode-editorWarning-foreground, #cca700);
    border: 1px solid color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 50%, transparent);
  }

  .meta-badge.pending {
    background: rgba(255,255,255,0.05);
    color: var(--vscode-descriptionForeground, #888);
    border: 1px solid rgba(255,255,255,0.09);
  }

  .csr-header-right {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    flex-shrink: 0;
  }

  /* ── Export-style buttons ── */
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

  .sign-btn {
    background: var(--vscode-button-background, #0e639c);
    color: var(--vscode-button-foreground, #fff);
    border-color: transparent;
  }

  .sign-btn:hover {
    background: var(--vscode-button-hoverBackground, #1177bb);
    border-color: transparent;
  }

  /* ── Summary bar ── */
  .summary-bar {
    display: flex;
    flex-wrap: wrap;
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 5%, var(--vscode-sideBar-background, #181825));
    border-bottom: 1px solid color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 20%, transparent);
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

  /* ── PEM toolbar ── */
  .pem-toolbar {
    display: flex;
    gap: 0.4rem;
    padding: 0.5rem 0.7rem 0.4rem;
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

  /* ── Key divider ── */
  .key-divider {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-top: 0.3rem;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .key-divider::before,
  .key-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 35%, transparent);
  }

  .key-divider-label {
    color: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 85%, var(--vscode-descriptionForeground, #888));
    flex-shrink: 0;
  }

  /* ── Unsaved banner ── */
  .unsaved-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    padding: 0.55rem 1.4rem;
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 10%, var(--vscode-sideBar-background, #181825));
    border-bottom: 1px solid color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 25%, transparent);
  }

  .unsaved-text {
    font-size: 0.78rem;
    color: var(--vscode-editorWarning-foreground, #cca700);
    flex: 1;
    min-width: 0;
  }

  /* ── Private key section internals ── */
  .key-note {
    margin: 0;
    padding: 0.35rem 0.7rem 0.55rem;
    font-size: 0.78rem;
    color: var(--vscode-descriptionForeground, #888);
    font-style: italic;
  }
</style>
