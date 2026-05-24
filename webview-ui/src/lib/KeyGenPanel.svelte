<script lang="ts">
  import { onMount } from 'svelte';
  import type { ExtToKeyGenMsg, KeyGenToExtMsg, StandaloneKeyData } from '../types';
  import SectionCard from './SectionCard.svelte';
  import FieldRow from './FieldRow.svelte';
  import HexValue from './HexValue.svelte';
  import InputDialog from './InputDialog.svelte';

  const vscode = acquireVsCodeApi();

  type State = 'idle' | 'generating' | 'done' | 'error';
  let state: State = 'idle';
  let selectedAlgorithm: string = 'EC-P256';
  let generatedKey: StandaloneKeyData | null = null;
  let errorMessage = '';

  // Input dialog (used for save-with-passphrase)
  let inputDialog: {
    requestId: string;
    title: string;
    icon?: string;
    description?: string;
    confirmLabel?: string;
    cancelLabel?: string;
    fields: Array<{
      id: string;
      label: string;
      type?: 'text' | 'password' | 'number' | 'date' | 'select';
      placeholder?: string;
      hint?: string;
      required?: boolean;
      options?: Array<{ value: string; label: string }>;
    }>;
  } | null = null;

  const ALGORITHMS = [
    { value: 'EC-P256',  label: 'EC P-256 (ECDSA / ECDH)' },
    { value: 'EC-P384',  label: 'EC P-384 (ECDSA / ECDH)' },
    { value: 'EC-P521',  label: 'EC P-521 (ECDSA / ECDH)' },
    { value: 'RSA-2048', label: 'RSA 2048-bit' },
    { value: 'RSA-4096', label: 'RSA 4096-bit' },
  ];

  $: keyDescription = generatedKey
    ? generatedKey.keySize
      ? `${generatedKey.algorithm} ${generatedKey.keySize}-bit`
      : generatedKey.namedCurve
      ? `${generatedKey.algorithm} (${generatedKey.namedCurve})`
      : generatedKey.algorithm
    : '';

  onMount(() => {
    window.addEventListener('message', (event: MessageEvent<ExtToKeyGenMsg>) => {
      const msg = event.data;
      switch (msg.type) {
        case 'keyGenGenerating':
          state = 'generating';
          errorMessage = '';
          break;
        case 'keyGenDone':
          generatedKey = msg.key;
          state = 'done';
          break;
        case 'keyGenError':
          errorMessage = msg.message;
          state = 'error';
          break;
        case 'requestInputDialog':
          inputDialog = {
            requestId: msg.requestId,
            title: msg.title,
            icon: msg.icon,
            description: msg.description,
            confirmLabel: msg.confirmLabel,
            cancelLabel: msg.cancelLabel,
            fields: msg.fields,
          };
          break;
      }
    });

    vscode.postMessage({ type: 'keyGenReady' } satisfies KeyGenToExtMsg);
  });

  function generate(): void {
    vscode.postMessage({
      type: 'keyGenGenerate',
      algorithm: selectedAlgorithm,
    } satisfies KeyGenToExtMsg);
  }

  function savePrivate(): void {
    vscode.postMessage({ type: 'keyGenSavePrivateKey' } satisfies KeyGenToExtMsg);
  }

  function savePublic(): void {
    vscode.postMessage({ type: 'keyGenSavePublicKey' } satisfies KeyGenToExtMsg);
  }

  function viewInViewer(): void {
    vscode.postMessage({ type: 'keyGenViewKey' } satisfies KeyGenToExtMsg);
  }

  function generateAnother(): void {
    state = 'idle';
    generatedKey = null;
    errorMessage = '';
  }

  function copy(value: string): void {
    vscode.postMessage({ type: 'copyToClipboard', value } satisfies KeyGenToExtMsg);
  }

  function handleInputDialogConfirm(e: CustomEvent<Record<string, string>>): void {
    if (!inputDialog) return;
    const { requestId } = inputDialog;
    inputDialog = null;
    vscode.postMessage({ type: 'inputDialogResponse', requestId, values: e.detail } satisfies KeyGenToExtMsg);
  }

  function handleInputDialogCancel(): void {
    if (!inputDialog) return;
    const { requestId } = inputDialog;
    inputDialog = null;
    vscode.postMessage({ type: 'inputDialogResponse', requestId, values: null } satisfies KeyGenToExtMsg);
  }
</script>

{#if inputDialog}
  <InputDialog
    title={inputDialog.title}
    icon={inputDialog.icon ?? ''}
    description={inputDialog.description ?? ''}
    fields={inputDialog.fields}
    confirmLabel={inputDialog.confirmLabel ?? 'OK'}
    cancelLabel={inputDialog.cancelLabel ?? 'Cancel'}
    on:confirm={handleInputDialogConfirm}
    on:cancel={handleInputDialogCancel}
  />
{/if}

<div class="key-gen">
  {#if state === 'idle' || state === 'error'}
    <SectionCard title="Generate Key Pair" icon="⚙">
      <div class="gen-form">
        <label class="algo-label" for="algo-select">Algorithm</label>
        <select id="algo-select" class="algo-select" bind:value={selectedAlgorithm}>
          {#each ALGORITHMS as a}
            <option value={a.value}>{a.label}</option>
          {/each}
        </select>

        {#if state === 'error'}
          <div class="error-banner" role="alert">
            <span class="error-icon">⚠</span>
            <span>{errorMessage}</span>
          </div>
        {/if}

        <button class="primary-btn" on:click={generate}>
          Generate Key Pair
        </button>
      </div>
    </SectionCard>

  {:else if state === 'generating'}
    <div class="generating-state">
      <div class="spinner" aria-hidden="true"></div>
      <p>Generating key pair…</p>
      <p class="hint">RSA 4096-bit may take a moment.</p>
    </div>

  {:else if state === 'done' && generatedKey}
    <!-- Overview -->
    <SectionCard title="Generated Key" icon="🔑">
      <FieldRow label="Algorithm" value={keyDescription} />
      {#if generatedKey.namedCurve}
        <FieldRow label="Curve" value={generatedKey.namedCurve} />
      {/if}
      {#if generatedKey.keySize}
        <FieldRow label="Key Size" value={`${generatedKey.keySize} bits`} />
      {/if}
    </SectionCard>

    <!-- Key ID -->
    <SectionCard title="Key Identifier" icon="🪪">
      <div class="hex-wrap">
        <div class="hex-label">SHA-1 of SPKI</div>
        <HexValue value={generatedKey.keyId} previewBytes={20}
          on:copy={() => copy(generatedKey.keyId)} />
      </div>
    </SectionCard>

    <!-- Public Key -->
    <SectionCard title="Public Key (SPKI PEM)" icon="🔓" collapsed>
      <div class="pem-wrap">
        <div class="pem-toolbar">
          <button class="copy-btn" on:click={() => copy(generatedKey.spkiPem)}>⧉ Copy</button>
        </div>
        <pre class="pem-block">{generatedKey.spkiPem}</pre>
      </div>
    </SectionCard>

    <!-- Private Key -->
    {#if generatedKey.pkcs8Pem}
      <SectionCard title="Private Key (PKCS#8 PEM)" icon="🔐" variant="key" collapsed>
        <div class="pem-wrap">
          <div class="pem-toolbar">
            <button class="copy-btn" on:click={() => copy(generatedKey.pkcs8Pem)}>⧉ Copy</button>
          </div>
          <pre class="pem-block">{generatedKey.pkcs8Pem}</pre>
        </div>
      </SectionCard>
    {/if}

    <!-- Actions -->
    <SectionCard title="Actions" icon="💾">
      <div class="actions-grid">
        <button class="action-btn" on:click={savePrivate}>
          🔐 Save Private Key…
        </button>
        <button class="action-btn secondary" on:click={savePublic}>
          🔓 Save Public Key…
        </button>
        <button class="action-btn secondary" on:click={viewInViewer}>
          🔍 Open in Key Viewer
        </button>
        <button class="action-btn secondary" on:click={generateAnother}>
          ↺ Generate Another
        </button>
      </div>
    </SectionCard>
  {/if}
</div>

<style>
  .key-gen {
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    max-width: 900px;
  }

  .gen-form {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    padding: 0.75rem;
  }

  .algo-label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--vscode-descriptionForeground, #888);
  }

  .algo-select {
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.18));
    border-radius: 4px;
    padding: 0.35rem 0.6rem;
    font-size: 0.85rem;
  }

  .error-banner {
    display: flex;
    align-items: flex-start;
    gap: 0.5rem;
    padding: 0.6rem 0.8rem;
    background: color-mix(in srgb, var(--vscode-errorForeground, #f44) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--vscode-errorForeground, #f44) 40%, transparent);
    border-radius: 6px;
    font-size: 0.82rem;
    color: var(--vscode-foreground);
  }

  .error-icon { flex-shrink: 0; }

  .primary-btn {
    align-self: flex-start;
    background: var(--vscode-button-background, #0078d4);
    color: var(--vscode-button-foreground, #fff);
    border: none;
    border-radius: 4px;
    padding: 0.4rem 1.1rem;
    font-size: 0.87rem;
    cursor: pointer;
    font-weight: 500;
  }

  .primary-btn:hover {
    background: var(--vscode-button-hoverBackground, #106ebe);
  }

  .generating-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 0.5rem;
    padding: 3rem 1rem;
    color: var(--vscode-descriptionForeground, #888);
    text-align: center;
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

  .hint {
    font-size: 0.78rem;
    color: var(--vscode-descriptionForeground, #888);
  }

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

  .actions-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    padding: 0.75rem;
  }

  .action-btn {
    background: var(--vscode-button-background, #0078d4);
    color: var(--vscode-button-foreground, #fff);
    border: none;
    border-radius: 4px;
    padding: 0.35rem 0.9rem;
    font-size: 0.82rem;
    cursor: pointer;
  }

  .action-btn:hover {
    background: var(--vscode-button-hoverBackground, #106ebe);
  }

  .action-btn.secondary {
    background: var(--vscode-button-secondaryBackground, rgba(255,255,255,0.1));
    color: var(--vscode-button-secondaryForeground, inherit);
  }

  .action-btn.secondary:hover {
    background: var(--vscode-button-secondaryHoverBackground, rgba(255,255,255,0.16));
  }
</style>
