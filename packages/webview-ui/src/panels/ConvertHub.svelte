<script lang="ts">
  import { onMount } from 'svelte';
  import type { ConvertToExtMsg, ExtToConvertMsg } from '../types';

  const vscode = acquireVsCodeApi();

  type ConvertMode = 'extractP12' | 'buildP12' | 'convertFormat' | 'bundleChain';

  let mode: ConvertMode = 'extractP12';

  // ── Extract P12 ──────────────────────────────────────────────────────────────
  let extractP12File = '';
  let extractPassphrase = '';
  let extractOutputMode: 'individual' | 'bundle' = 'bundle';
  let extractIncludeKey = true;

  // ── Build P12 ─────────────────────────────────────────────────────────────────
  let buildCertFile = '';
  let buildKeyFile = '';
  let buildPassphrase = '';

  // ── Convert Format ────────────────────────────────────────────────────────────
  let convertAssetType: 'cert' | 'key' = 'cert';
  let convertDirection: 'pem-to-der' | 'der-to-pem' = 'pem-to-der';
  let convertInputFile = '';

  // ── Bundle Chain ──────────────────────────────────────────────────────────────
  let bundleFileCount = 0;
  let bundleFileLabel = '';

  // ── Status ────────────────────────────────────────────────────────────────────
  type Status = { type: 'idle' } | { type: 'working' } | { type: 'success'; message: string } | { type: 'error'; message: string };
  let status: Status = { type: 'idle' };

  function post(msg: ConvertToExtMsg): void {
    vscode.postMessage(msg);
  }

  onMount(() => {
    window.addEventListener('message', (event: MessageEvent<ExtToConvertMsg>) => {
      const msg = event.data;
      switch (msg.type) {
        case 'convertFileSelected': {
          const { slotId, fileName, fileCount } = msg;
          if (slotId === 'p12Input')      extractP12File    = fileName;
          else if (slotId === 'certInput')     buildCertFile     = fileName;
          else if (slotId === 'keyInput')      buildKeyFile      = fileName;
          else if (slotId === 'convertInput')  convertInputFile  = fileName;
          else if (slotId === 'bundleFiles') {
            bundleFileCount = fileCount ?? 0;
            bundleFileLabel = fileName;
          }
          status = { type: 'idle' };
          break;
        }
        case 'convertResult':
          status = { type: 'success', message: msg.message };
          break;
        case 'convertError':
          status = { type: 'error', message: msg.message };
          break;
      }
    });
    post({ type: 'convertReady' });
  });

  // Reset convert input when asset type changes (cert vs key use different file types)
  $: if (convertAssetType) { convertInputFile = ''; }

  function switchMode(m: ConvertMode): void {
    mode = m;
    status = { type: 'idle' };
  }

  function browseP12(): void {
    post({ type: 'convertPickFile', slotId: 'p12Input', filters: { 'PKCS#12': ['p12', 'pfx'] } });
  }

  function browseCert(): void {
    post({ type: 'convertPickFile', slotId: 'certInput', filters: { Certificate: ['pem', 'crt', 'cer', 'der'] } });
  }

  function browseKey(): void {
    post({ type: 'convertPickFile', slotId: 'keyInput', filters: { 'Private Key': ['pem', 'key', 'der', 'pk8'] } });
  }

  function clearKey(): void {
    buildKeyFile = '';
  }

  function browseConvertInput(): void {
    const isKey = convertAssetType === 'key';
    post({
      type: 'convertPickFile',
      slotId: 'convertInput',
      filters: isKey
        ? { 'Private Key': ['pem', 'key', 'der', 'pk8'] }
        : { Certificate: ['pem', 'crt', 'cer', 'der'] },
    });
  }

  function browseBundleFiles(): void {
    post({
      type: 'convertPickFiles',
      slotId: 'bundleFiles',
      filters: { Certificate: ['pem', 'crt', 'cer', 'der'] },
    });
  }

  function doExtractP12(): void {
    if (!extractP12File) { status = { type: 'error', message: 'Select a P12 file first.' }; return; }
    status = { type: 'working' };
    post({ type: 'convertExecuteExtractP12', passphrase: extractPassphrase, outputMode: extractOutputMode, includeKey: extractIncludeKey });
  }

  function doBuildP12(): void {
    if (!buildCertFile) { status = { type: 'error', message: 'Select a certificate file first.' }; return; }
    status = { type: 'working' };
    post({ type: 'convertExecuteBuildP12', passphrase: buildPassphrase, includeKey: !!buildKeyFile });
  }

  function doConvertFormat(): void {
    if (!convertInputFile) { status = { type: 'error', message: 'Select an input file first.' }; return; }
    status = { type: 'working' };
    post({ type: 'convertExecuteConvertFormat', assetType: convertAssetType, direction: convertDirection });
  }

  function doBundleChain(): void {
    if (!bundleFileCount) { status = { type: 'error', message: 'Select certificate files first.' }; return; }
    status = { type: 'working' };
    const orderedSlotIds = Array.from({ length: bundleFileCount }, (_, i) => `bundleFiles_${i}`);
    post({ type: 'convertExecuteBundleChain', orderedSlotIds });
  }

  const MODES: { id: ConvertMode; label: string; icon: string }[] = [
    { id: 'extractP12',    label: 'Extract P12',     icon: '📤' },
    { id: 'buildP12',      label: 'Build P12',        icon: '📦' },
    { id: 'convertFormat', label: 'Convert Format',   icon: '↔' },
    { id: 'bundleChain',   label: 'Bundle Chain',     icon: '🔗' },
  ];
</script>

<div class="hub">
  <header class="hub-header">
    <h1 class="hub-title">🔄 Format Conversion Hub</h1>
    <p class="hub-subtitle">Convert, extract, and package certificate files</p>
  </header>

  <nav class="mode-tabs" role="tablist">
    {#each MODES as m}
      <button
        class="mode-tab"
        class:active={mode === m.id}
        role="tab"
        aria-selected={mode === m.id}
        on:click={() => switchMode(m.id)}
      >
        <span class="tab-icon">{m.icon}</span>
        <span class="tab-label">{m.label}</span>
      </button>
    {/each}
  </nav>

  <section class="mode-panel">

    <!-- ── Extract P12 ─────────────────────────────────────────────────────── -->
    {#if mode === 'extractP12'}
      <div class="mode-description">
        <strong>openssl pkcs12 -nokeys -clcerts</strong> — extract certificates and/or private key from a P12/PFX file into separate PEM files.
      </div>
      <div class="form">
        <div class="field">
          <label class="field-label">P12 / PFX File</label>
          <div class="file-row">
            <span class="file-name" class:empty={!extractP12File}>
              {extractP12File || 'No file selected'}
            </span>
            <button class="btn btn-secondary" on:click={browseP12}>Browse…</button>
          </div>
        </div>

        <div class="field">
          <label class="field-label" for="extract-pass">Password</label>
          <input id="extract-pass" class="text-input" type="password" placeholder="Leave empty if not password-protected" bind:value={extractPassphrase} />
        </div>

        <div class="field">
          <label class="field-label">Certificate Output</label>
          <div class="radio-group">
            <label class="radio-label">
              <input type="radio" bind:group={extractOutputMode} value="bundle" />
              Save as one multi-cert PEM bundle
            </label>
            <label class="radio-label">
              <input type="radio" bind:group={extractOutputMode} value="individual" />
              Save as individual PEM files (one dialog per cert)
            </label>
          </div>
        </div>

        <div class="field">
          <label class="checkbox-label">
            <input type="checkbox" bind:checked={extractIncludeKey} />
            Also export private key (if present in the P12)
          </label>
        </div>

        <div class="action-row">
          <button class="btn btn-primary" on:click={doExtractP12} disabled={status.type === 'working'}>
            {status.type === 'working' ? '⏳ Extracting…' : '📤 Extract'}
          </button>
        </div>
      </div>

    <!-- ── Build P12 ────────────────────────────────────────────────────────── -->
    {:else if mode === 'buildP12'}
      <div class="mode-description">
        <strong>openssl pkcs12 -export</strong> — merge a PEM certificate (or chain) and optional private key into a PKCS#12 / PFX file.
      </div>
      <div class="form">
        <div class="field">
          <label class="field-label">Certificate File (PEM or DER, may contain a chain)</label>
          <div class="file-row">
            <span class="file-name" class:empty={!buildCertFile}>
              {buildCertFile || 'No file selected'}
            </span>
            <button class="btn btn-secondary" on:click={browseCert}>Browse…</button>
          </div>
        </div>

        <div class="field">
          <label class="field-label">Private Key (optional — leave blank for certs-only P12)</label>
          <div class="file-row">
            <span class="file-name" class:empty={!buildKeyFile}>
              {buildKeyFile || 'No file selected'}
            </span>
            <button class="btn btn-secondary" on:click={browseKey}>Browse…</button>
            {#if buildKeyFile}
              <button class="btn btn-ghost" title="Clear key" on:click={clearKey}>✕</button>
            {/if}
          </div>
        </div>

        <div class="field">
          <label class="field-label" for="build-pass">P12 Password</label>
          <input id="build-pass" class="text-input" type="password" placeholder="Leave empty for no password" bind:value={buildPassphrase} />
          {#if buildKeyFile}
            <span class="field-hint">Password protects the private key inside the P12.</span>
          {:else}
            <span class="field-hint">Password is ignored when no private key is included.</span>
          {/if}
        </div>

        <div class="action-row">
          <button class="btn btn-primary" on:click={doBuildP12} disabled={status.type === 'working'}>
            {status.type === 'working' ? '⏳ Building…' : '📦 Build P12'}
          </button>
        </div>
      </div>

    <!-- ── Convert Format ──────────────────────────────────────────────────── -->
    {:else if mode === 'convertFormat'}
      <div class="mode-description">
        <strong>openssl x509 -inform DER -outform PEM</strong> — convert a certificate or private key between PEM and DER binary formats.
      </div>
      <div class="form">
        <div class="field">
          <label class="field-label">Asset Type</label>
          <div class="toggle-group">
            <button class="toggle-btn" class:active={convertAssetType === 'cert'} on:click={() => convertAssetType = 'cert'}>Certificate</button>
            <button class="toggle-btn" class:active={convertAssetType === 'key'} on:click={() => convertAssetType = 'key'}>Private Key</button>
          </div>
        </div>

        <div class="field">
          <label class="field-label">Direction</label>
          <div class="toggle-group">
            <button class="toggle-btn" class:active={convertDirection === 'pem-to-der'} on:click={() => convertDirection = 'pem-to-der'}>PEM → DER</button>
            <button class="toggle-btn" class:active={convertDirection === 'der-to-pem'} on:click={() => convertDirection = 'der-to-pem'}>DER → PEM</button>
          </div>
        </div>

        <div class="field">
          <label class="field-label">
            Input File ({convertDirection === 'pem-to-der' ? 'PEM' : 'DER'} {convertAssetType === 'cert' ? 'Certificate' : 'Private Key'})
          </label>
          <div class="file-row">
            <span class="file-name" class:empty={!convertInputFile}>
              {convertInputFile || 'No file selected'}
            </span>
            <button class="btn btn-secondary" on:click={browseConvertInput}>Browse…</button>
          </div>
        </div>

        <div class="action-row">
          <button class="btn btn-primary" on:click={doConvertFormat} disabled={status.type === 'working'}>
            {status.type === 'working' ? '⏳ Converting…' : '↔ Convert'}
          </button>
        </div>
      </div>

    <!-- ── Bundle Chain ─────────────────────────────────────────────────────── -->
    {:else if mode === 'bundleChain'}
      <div class="mode-description">
        <strong>cat cert.pem ca.pem root.pem &gt; bundle.pem</strong> — merge multiple PEM or DER certificate files into a single multi-cert PEM bundle (e.g. for TLS chain configuration).
      </div>
      <div class="form">
        <div class="field">
          <label class="field-label">Certificate Files</label>
          <div class="file-row">
            <span class="file-name" class:empty={!bundleFileCount}>
              {bundleFileCount ? bundleFileLabel : 'No files selected'}
            </span>
            <button class="btn btn-secondary" on:click={browseBundleFiles}>Pick Files…</button>
          </div>
          <span class="field-hint">Select all certificates in the correct order (e.g. end-entity first, then intermediate(s), then root).</span>
        </div>

        <div class="action-row">
          <button class="btn btn-primary" on:click={doBundleChain} disabled={status.type === 'working'}>
            {status.type === 'working' ? '⏳ Bundling…' : '🔗 Bundle'}
          </button>
        </div>
      </div>
    {/if}

    <!-- ── Status area ─────────────────────────────────────────────────────── -->
    {#if status.type !== 'idle'}
      <div class="status-area" class:success={status.type === 'success'} class:error={status.type === 'error'} class:working={status.type === 'working'}>
        {#if status.type === 'working'}
          <span class="spinner"></span> Working…
        {:else if status.type === 'success'}
          ✅ {status.message}
        {:else if status.type === 'error'}
          ⚠️ {status.message}
        {/if}
      </div>
    {/if}

  </section>
</div>

<style>
  :global(*) { box-sizing: border-box; }

  :global(body) {
    margin: 0;
    padding: 0;
    font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif);
    font-size: var(--vscode-font-size, 13px);
    color: var(--vscode-editor-foreground, #cdd6f4);
    background-color: var(--vscode-editor-background, #1e1e2e);
    line-height: 1.5;
  }

  .hub {
    max-width: 680px;
    margin: 0 auto;
    padding: 24px 20px 48px;
  }

  .hub-header {
    margin-bottom: 20px;
  }

  .hub-title {
    font-size: 1.4em;
    font-weight: 600;
    margin: 0 0 4px;
    color: var(--vscode-editor-foreground);
  }

  .hub-subtitle {
    margin: 0;
    opacity: 0.7;
    font-size: 0.92em;
  }

  /* ── Mode tabs ─────────────────────────────────────────────────────────── */
  .mode-tabs {
    display: flex;
    gap: 2px;
    border-bottom: 1px solid var(--vscode-panel-border, #3c3c3c);
    margin-bottom: 20px;
  }

  .mode-tab {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 7px 14px;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    cursor: pointer;
    color: var(--vscode-editor-foreground);
    opacity: 0.65;
    font-size: 0.92em;
    transition: opacity 0.1s;
    white-space: nowrap;
  }

  .mode-tab:hover { opacity: 0.9; }

  .mode-tab.active {
    opacity: 1;
    border-bottom-color: var(--vscode-focusBorder, #007fd4);
    font-weight: 600;
  }

  .tab-icon { font-size: 1em; }

  /* ── Mode panel ────────────────────────────────────────────────────────── */
  .mode-panel {
    animation: fade-in 0.12s ease;
  }

  @keyframes fade-in {
    from { opacity: 0; transform: translateY(4px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .mode-description {
    background: var(--vscode-textBlockQuote-background, rgba(255,255,255,0.05));
    border-left: 3px solid var(--vscode-focusBorder, #007fd4);
    padding: 8px 12px;
    border-radius: 0 4px 4px 0;
    font-size: 0.9em;
    margin-bottom: 20px;
    opacity: 0.85;
    font-family: var(--vscode-editor-font-family, monospace);
  }

  /* ── Form elements ─────────────────────────────────────────────────────── */
  .form { display: flex; flex-direction: column; gap: 16px; }

  .field { display: flex; flex-direction: column; gap: 5px; }

  .field-label {
    font-size: 0.88em;
    font-weight: 600;
    opacity: 0.8;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .field-hint {
    font-size: 0.82em;
    opacity: 0.6;
  }

  .file-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .file-name {
    flex: 1;
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.9em;
    padding: 5px 8px;
    background: var(--vscode-input-background, #2d2d2d);
    border: 1px solid var(--vscode-input-border, #3c3c3c);
    border-radius: 3px;
  }

  .file-name.empty { opacity: 0.45; }

  .text-input {
    padding: 5px 8px;
    background: var(--vscode-input-background, #2d2d2d);
    border: 1px solid var(--vscode-input-border, #3c3c3c);
    border-radius: 3px;
    color: var(--vscode-input-foreground, inherit);
    font-family: inherit;
    font-size: inherit;
    width: 100%;
  }

  .text-input:focus {
    outline: none;
    border-color: var(--vscode-focusBorder, #007fd4);
  }

  .radio-group { display: flex; flex-direction: column; gap: 6px; }

  .radio-label,
  .checkbox-label {
    display: flex;
    align-items: center;
    gap: 7px;
    cursor: pointer;
    font-size: 0.93em;
  }

  /* ── Toggle group ────────────────────────────────────────────────────────── */
  .toggle-group {
    display: flex;
    gap: 0;
    border: 1px solid var(--vscode-input-border, #3c3c3c);
    border-radius: 4px;
    overflow: hidden;
    width: fit-content;
  }

  .toggle-btn {
    padding: 5px 14px;
    background: none;
    border: none;
    border-right: 1px solid var(--vscode-input-border, #3c3c3c);
    cursor: pointer;
    color: var(--vscode-editor-foreground);
    opacity: 0.6;
    font-size: 0.9em;
    transition: background 0.1s, opacity 0.1s;
  }

  .toggle-btn:last-child { border-right: none; }
  .toggle-btn:hover { opacity: 0.9; background: var(--vscode-toolbar-hoverBackground, rgba(255,255,255,0.06)); }

  .toggle-btn.active {
    opacity: 1;
    background: var(--vscode-button-background, #0e639c);
    color: var(--vscode-button-foreground, #fff);
  }

  /* ── Buttons ─────────────────────────────────────────────────────────────── */
  .action-row { margin-top: 6px; }

  .btn {
    padding: 6px 14px;
    border: 1px solid transparent;
    border-radius: 3px;
    cursor: pointer;
    font-size: 0.93em;
    font-family: inherit;
    transition: opacity 0.1s;
  }

  .btn:disabled { opacity: 0.45; cursor: not-allowed; }

  .btn-primary {
    background: var(--vscode-button-background, #0e639c);
    color: var(--vscode-button-foreground, #fff);
    border-color: var(--vscode-button-background, #0e639c);
  }
  .btn-primary:hover:not(:disabled) { opacity: 0.85; }

  .btn-secondary {
    background: var(--vscode-button-secondaryBackground, #3a3d41);
    color: var(--vscode-button-secondaryForeground, inherit);
    border-color: var(--vscode-button-secondaryBackground, #3a3d41);
  }
  .btn-secondary:hover:not(:disabled) { opacity: 0.8; }

  .btn-ghost {
    background: none;
    color: var(--vscode-editor-foreground);
    opacity: 0.55;
    padding: 5px 8px;
  }
  .btn-ghost:hover { opacity: 0.9; }

  /* ── Status area ──────────────────────────────────────────────────────────── */
  .status-area {
    margin-top: 20px;
    padding: 10px 14px;
    border-radius: 4px;
    font-size: 0.93em;
    display: flex;
    align-items: center;
    gap: 8px;
    border: 1px solid transparent;
  }

  .status-area.success {
    background: var(--vscode-inputValidation-infoBackground, rgba(0, 127, 212, 0.15));
    border-color: var(--vscode-inputValidation-infoBorder, #007fd4);
  }

  .status-area.error {
    background: var(--vscode-inputValidation-errorBackground, rgba(200, 50, 50, 0.15));
    border-color: var(--vscode-inputValidation-errorBorder, #be1100);
  }

  .status-area.working {
    opacity: 0.75;
  }

  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid var(--vscode-editor-foreground);
    border-top-color: transparent;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    flex-shrink: 0;
  }

  @keyframes spin { to { transform: rotate(360deg); } }
</style>
