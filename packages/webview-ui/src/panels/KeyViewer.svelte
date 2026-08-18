<script lang="ts">
  import { onMount } from 'svelte';
  import type { ExtToKeyViewerMsg, KeyViewerToExtMsg, StandaloneKeyData } from '../types';
  import SectionCard from '../lib/SectionCard.svelte';
  import FieldRow from '../lib/FieldRow.svelte';
  import HexValue from '../lib/HexValue.svelte';
  import PassphraseDialog from '../lib/PassphraseDialog.svelte';

  const vscode = acquireVsCodeApi();

  type State = 'idle' | 'loading' | 'ready' | 'error';
  let state: State = 'idle';
  let keyData: StandaloneKeyData | null = null;
  let errorMessage = '';

  // Passphrase dialog
  let passphraseRequest: {
    requestId: string;
    fileName: string;
    title?: string;
    description?: string;
    buttonLabel?: string;
    requireConfirm?: boolean;
  } | null = null;

  // Export options
  let privateExportFormat: string = 'pkcs8-pem';
  let privateExportEncrypt = false;
  let publicExportFormat: string = 'spki-pem';

  $: isRsa = keyData?.algorithm === 'RSA' || keyData?.algorithm === 'RSA-PSS';
  $: isEc = keyData?.algorithm === 'EC';

  // Available private key export formats depend on algorithm
  $: privFormats = isRsa
    ? [
        { value: 'pkcs8-pem', label: 'PKCS#8 PEM (BEGIN PRIVATE KEY)' },
        { value: 'pkcs8-der', label: 'PKCS#8 DER' },
        { value: 'pkcs1-pem', label: 'PKCS#1 PEM (BEGIN RSA PRIVATE KEY)' },
        { value: 'pkcs1-der', label: 'PKCS#1 DER' },
      ]
    : isEc
    ? [
        { value: 'pkcs8-pem', label: 'PKCS#8 PEM (BEGIN PRIVATE KEY)' },
        { value: 'pkcs8-der', label: 'PKCS#8 DER' },
        { value: 'sec1-pem', label: 'SEC1 PEM (BEGIN EC PRIVATE KEY)' },
        { value: 'sec1-der', label: 'SEC1 DER' },
      ]
    : [
        { value: 'pkcs8-pem', label: 'PKCS#8 PEM (BEGIN PRIVATE KEY)' },
        { value: 'pkcs8-der', label: 'PKCS#8 DER' },
      ];

  $: pubFormats = [
    { value: 'spki-pem', label: 'SPKI PEM (BEGIN PUBLIC KEY)' },
    { value: 'spki-der', label: 'SPKI DER' },
  ];

  const FORMAT_LABELS: Record<string, string> = {
    'pkcs8-pem': 'PKCS#8 PEM',
    'encrypted-pkcs8-pem': 'PKCS#8 PEM (encrypted)',
    'pkcs1-pem': 'PKCS#1 PEM',
    'sec1-pem': 'SEC1 PEM',
    'spki-pem': 'SPKI PEM',
    'pkcs1-pub-pem': 'PKCS#1 Public PEM',
    'spki-der': 'SPKI DER',
    'der': 'DER (binary)',
    'unknown': 'Unknown',
  };

  onMount(() => {
    window.addEventListener('message', (event: MessageEvent<ExtToKeyViewerMsg>) => {
      const msg = event.data;
      switch (msg.type) {
        case 'keyLoading':
          state = 'loading';
          keyData = null;
          errorMessage = '';
          passphraseRequest = null;
          break;
        case 'keyData':
          keyData = msg.key;
          state = 'ready';
          // Reset export format to sensible default
          privateExportFormat = 'pkcs8-pem';
          privateExportEncrypt = false;
          publicExportFormat = 'spki-pem';
          break;
        case 'keyError':
          errorMessage = msg.message;
          state = 'error';
          break;
        case 'requestPassphrase':
          passphraseRequest = {
            requestId: msg.requestId,
            fileName: msg.fileName,
            title: msg.title,
            description: msg.description,
            buttonLabel: msg.buttonLabel,
            requireConfirm: msg.requireConfirm,
          };
          break;
      }
    });

    vscode.postMessage({ type: 'keyViewerReady' } satisfies KeyViewerToExtMsg);
  });

  function copy(value: string): void {
    vscode.postMessage({ type: 'copyToClipboard', value } satisfies KeyViewerToExtMsg);
  }

  function exportPrivateKey(): void {
    if (!keyData) return;
    const base = (keyData.algorithm + '-key').toLowerCase().replace(/[^a-z0-9]/g, '-');
    vscode.postMessage({
      type: 'exportPrivateKey',
      format: privateExportFormat as 'pkcs8-pem' | 'pkcs8-der' | 'pkcs1-pem' | 'pkcs1-der' | 'sec1-pem' | 'sec1-der',
      encrypt: privateExportEncrypt,
      suggestedName: base,
    } satisfies KeyViewerToExtMsg);
  }

  function exportPublicKey(): void {
    if (!keyData) return;
    const base = (keyData.algorithm + '-pubkey').toLowerCase().replace(/[^a-z0-9]/g, '-');
    vscode.postMessage({
      type: 'exportPublicKey',
      format: publicExportFormat as 'spki-pem' | 'spki-der',
      suggestedName: base,
    } satisfies KeyViewerToExtMsg);
  }

  function handlePassphraseSubmit(e: CustomEvent<string>): void {
    if (!passphraseRequest) return;
    const { requestId } = passphraseRequest;
    passphraseRequest = null;
    vscode.postMessage({ type: 'passphraseResponse', requestId, passphrase: e.detail } satisfies KeyViewerToExtMsg);
  }

  function handlePassphraseCancel(): void {
    if (!passphraseRequest) return;
    const { requestId } = passphraseRequest;
    passphraseRequest = null;
    vscode.postMessage({ type: 'passphraseResponse', requestId, passphrase: null } satisfies KeyViewerToExtMsg);
  }
</script>

{#if passphraseRequest}
  <PassphraseDialog
    fileName={passphraseRequest.fileName}
    title={passphraseRequest.title ?? 'Encrypted Key'}
    description={passphraseRequest.description}
    buttonLabel={passphraseRequest.buttonLabel ?? 'Open'}
    requireConfirm={passphraseRequest.requireConfirm ?? false}
    on:submit={handlePassphraseSubmit}
    on:cancel={handlePassphraseCancel}
  />
{/if}

<div class="key-viewer">
  {#if state === 'idle'}
    <div class="empty-state">
      <span class="empty-icon">🔑</span>
      <p>Open a key file to inspect it.</p>
      <p class="hint">Use <strong>X.509 Toolkit: Open Key File</strong> from the command palette.</p>
    </div>

  {:else if state === 'loading'}
    <div class="loading-state">
      <div class="spinner" aria-hidden="true"></div>
      <p>Loading key…</p>
    </div>

  {:else if state === 'error'}
    <div class="error-banner" role="alert">
      <span class="error-icon">⚠</span>
      <span>{errorMessage}</span>
    </div>

  {:else if state === 'ready' && keyData}
    <!-- Overview -->
    <SectionCard title="Key Overview" icon="🔑">
      <FieldRow label="Kind" value={keyData.kind === 'private' ? 'Private Key' : 'Public Key'} />
      <FieldRow label="Algorithm" value={
        keyData.keySize
          ? `${keyData.algorithm} ${keyData.keySize}-bit`
          : keyData.namedCurve
          ? `${keyData.algorithm} (${keyData.namedCurve})`
          : keyData.algorithm
      } />
      {#if keyData.namedCurve}
        <FieldRow label="Curve" value={keyData.namedCurve} />
      {/if}
      {#if keyData.keySize}
        <FieldRow label="Key Size" value={`${keyData.keySize} bits`} />
      {/if}
      <FieldRow label="Source Format" value={FORMAT_LABELS[keyData.inputFormat] ?? keyData.inputFormat} />
      {#if keyData.kind === 'private'}
        <FieldRow label="Encrypted on Disk" value={keyData.isEncrypted ? 'Yes' : 'No'} />
      {/if}
    </SectionCard>

    <!-- Key ID -->
    <SectionCard title="Key Identifier" icon="🪪">
      <div class="hex-wrap">
        <div class="hex-label">SHA-1 of SPKI (SubjectKeyIdentifier)</div>
        <HexValue value={keyData.keyId} previewBytes={20}
          on:copy={() => copy(keyData.keyId)} />
      </div>
    </SectionCard>

    <!-- RSA Details -->
    {#if (keyData.algorithm === 'RSA' || keyData.algorithm === 'RSA-PSS') && keyData.modulus}
      <SectionCard title="RSA Parameters" icon="🔢" collapsed>
        <div class="hex-wrap">
          <div class="hex-label">Modulus ({keyData.keySize} bits)</div>
          <HexValue value={keyData.modulus} previewBytes={16}
            on:copy={() => copy(keyData.modulus)} />
        </div>
        {#if keyData.publicExponent}
          <div class="hex-wrap">
            <div class="hex-label">Public Exponent</div>
            <HexValue value={keyData.publicExponent} previewBytes={4}
              on:copy={() => copy(keyData.publicExponent)} />
          </div>
        {/if}
      </SectionCard>
    {/if}

    <!-- Public Key (SPKI) -->
    <SectionCard title="Public Key (SPKI PEM)" icon="🔓" collapsed>
      <div class="pem-wrap">
        <div class="pem-toolbar">
          <button class="copy-btn" on:click={() => copy(keyData.spkiPem)}>⧉ Copy</button>
        </div>
        <pre class="pem-block">{keyData.spkiPem}</pre>
      </div>
    </SectionCard>

    <!-- Private Key (PKCS#8) -->
    {#if keyData.kind === 'private' && keyData.pkcs8Pem}
      <SectionCard title="Private Key (PKCS#8 PEM)" icon="🔐" variant="key" collapsed>
        <div class="pem-wrap">
          <div class="pem-toolbar">
            <button class="copy-btn" on:click={() => copy(keyData.pkcs8Pem)}>⧉ Copy</button>
          </div>
          <pre class="pem-block">{keyData.pkcs8Pem}</pre>
        </div>
      </SectionCard>
    {/if}

    <!-- Export -->
    <SectionCard title="Export" icon="💾">
      {#if keyData.kind === 'private'}
        <div class="export-row">
          <span class="export-label">Private Key Format</span>
          <select class="export-select" bind:value={privateExportFormat}>
            {#each privFormats as f}
              <option value={f.value}>{f.label}</option>
            {/each}
          </select>
          <label class="encrypt-check">
            <input type="checkbox" bind:checked={privateExportEncrypt} />
            Encrypt
          </label>
          <button class="action-btn" on:click={exportPrivateKey}>Save Private Key…</button>
        </div>
      {/if}
      <div class="export-row">
        <span class="export-label">Public Key Format</span>
        <select class="export-select" bind:value={publicExportFormat}>
          {#each pubFormats as f}
            <option value={f.value}>{f.label}</option>
          {/each}
        </select>
        <button class="action-btn" on:click={exportPublicKey}>Save Public Key…</button>
      </div>
    </SectionCard>
  {/if}
</div>

<style>
  .key-viewer {
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    max-width: 900px;
  }

  .empty-state,
  .loading-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 3rem 1rem;
    color: var(--vscode-descriptionForeground, #888);
    text-align: center;
  }

  .empty-icon { font-size: 2rem; }

  .hint {
    font-size: 0.78rem;
    color: var(--vscode-descriptionForeground, #888);
  }

  .spinner {
    width: 28px;
    height: 28px;
    border: 3px solid var(--vscode-panel-border, rgba(255,255,255,0.1));
    border-top-color: var(--vscode-progressBar-background, #0078d4);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .error-banner {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.75rem 1rem;
    background: color-mix(in srgb, var(--vscode-errorForeground, #f44) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--vscode-errorForeground, #f44) 40%, transparent);
    border-radius: 6px;
    color: var(--vscode-foreground);
    white-space: pre-wrap;
    font-size: 0.82rem;
  }

  .error-icon { flex-shrink: 0; }

  .hex-wrap {
    padding: 0.5rem 0.7rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .hex-label {
    font-size: 0.67rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--vscode-descriptionForeground, #888);
  }

  .pem-wrap {
    padding: 0.5rem 0.7rem;
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  .pem-toolbar {
    display: flex;
    justify-content: flex-end;
  }

  .pem-block {
    margin: 0;
    padding: 0.5rem;
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.7rem;
    white-space: pre-wrap;
    word-break: break-all;
    background: var(--vscode-input-background, rgba(0,0,0,0.18));
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.08));
    border-radius: 4px;
    color: var(--vscode-editor-foreground);
    max-height: 220px;
    overflow-y: auto;
  }

  .copy-btn {
    background: none;
    border: 1px solid var(--vscode-button-secondaryBackground, rgba(255,255,255,0.12));
    color: var(--vscode-button-secondaryForeground, inherit);
    border-radius: 4px;
    padding: 0.18rem 0.5rem;
    cursor: pointer;
    font-size: 0.72rem;
  }

  .copy-btn:hover {
    background: var(--vscode-button-secondaryHoverBackground, rgba(255,255,255,0.08));
  }

  .export-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.5rem 0.7rem;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.04));
  }

  .export-row:last-child { border-bottom: none; }

  .export-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--vscode-descriptionForeground, #888);
    min-width: 130px;
  }

  .export-select {
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.18));
    border-radius: 4px;
    padding: 0.25rem 0.5rem;
    font-size: 0.8rem;
    flex: 1;
    min-width: 200px;
  }

  .encrypt-check {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    font-size: 0.8rem;
    cursor: pointer;
    white-space: nowrap;
  }

  .action-btn {
    background: var(--vscode-button-background, #0078d4);
    color: var(--vscode-button-foreground, #fff);
    border: none;
    border-radius: 4px;
    padding: 0.3rem 0.8rem;
    cursor: pointer;
    font-size: 0.8rem;
    white-space: nowrap;
  }

  .action-btn:hover {
    background: var(--vscode-button-hoverBackground, #106ebe);
  }
</style>
