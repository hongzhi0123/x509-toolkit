<script lang="ts">
  import { onMount } from 'svelte';
  import type { CertCreateParams, KeyAlgorithm, CreateCertToExtMsg, ExtToCreateCertMsg } from '../types';

  declare function acquireVsCodeApi(): {
    postMessage(msg: CreateCertToExtMsg): void;
    getState(): unknown;
    setState(state: unknown): void;
  };
  const vscode = acquireVsCodeApi();

  // ── defaults ──────────────────────────────────────────────────────────────
  let cn           = '';
  let o            = '';
  let ou           = '';
  let c            = '';
  let st           = '';
  let l            = '';
  let email        = '';
  let dnsNames     = '';
  let ipAddresses  = '';

  let keyAlgorithm: KeyAlgorithm = 'RSA-2048';
  let validityDays = 365;
  let isCA         = false;

  let keyUsageDigitalSignature = true;
  let keyUsageKeyEncipherment  = true;
  let keyUsageDataEncipherment = false;
  let keyUsageKeyCertSign      = false;
  let keyUsageCRLSign          = false;

  let ekuServerAuth      = true;
  let ekuClientAuth      = true;
  let ekuCodeSigning     = false;
  let ekuEmailProtection = false;

  let signingMode: 'self-signed' | 'ca-signed' | 'csr' = 'self-signed';
  let caCertSubject  = '';
  let caKeyDesc      = '';

  let password         = '';
  let passwordConfirm  = '';
  let keyPassword      = '';  // private-key password for CSR mode

  // ── state ────────────────────────────────────────────────────────────────
  type PanelState = 'idle' | 'generating' | 'done' | 'csrReady';
  let panelState: PanelState = 'idle';
  let errorMsg = '';
  let csrPemReady = '';  // CSR PEM returned by csrReady;

  // ── derived smart defaults ───────────────────────────────────────────────
  $: isEC = keyAlgorithm.startsWith('EC');
  $: isCsrMode = signingMode === 'csr';

  // When switching to CA mode, auto-enable keyCertSign + cRLSign
  $: if (isCA) {
    keyUsageKeyCertSign  = true;
    keyUsageCRLSign      = true;
    keyUsageKeyEncipherment  = false;
    ekuServerAuth  = false;
    ekuClientAuth  = false;
  }

  // EC keys don't support key encipherment
  $: if (isEC) {
    keyUsageKeyEncipherment  = false;
    keyUsageDataEncipherment = false;
  }

  $: passwordMismatch = password !== passwordConfirm;

  // ── validation ───────────────────────────────────────────────────────────
  function validate(): string | null {
    if (!cn.trim()) return 'Common Name (CN) is required.';
    if (!Number.isInteger(validityDays) || validityDays < 1) return 'Validity must be a positive integer.';
    if (!isCsrMode && password !== passwordConfirm) return 'Passwords do not match.';
    if (signingMode === 'ca-signed' && !caCertSubject) return 'Please select a CA certificate.';
    if (signingMode === 'ca-signed' && !caKeyDesc)     return 'Please select the CA private key.';
    return null;
  }

  // ── message handling ──────────────────────────────────────────────────────
  onMount(() => {
    window.addEventListener('message', (ev: MessageEvent<ExtToCreateCertMsg>) => {
      const msg = ev.data;
      switch (msg.type) {
        case 'caCertLoaded':
          caCertSubject = msg.subject;
          errorMsg = '';
          break;
        case 'caKeyLoaded':
          caKeyDesc = msg.description;
          errorMsg = '';
          break;
        case 'generating':
          panelState = 'generating';
          errorMsg = '';
          break;
        case 'done':
          panelState = 'done';
          break;
        case 'csrReady':
          csrPemReady = msg.csrPem;
          panelState = 'csrReady';
          errorMsg = '';
          break;
        case 'error':
          errorMsg = msg.message;
          panelState = 'idle';
          break;
      }
    });
    vscode.postMessage({ type: 'ready' });
  });

  // ── actions ───────────────────────────────────────────────────────────────
  function pickCaCert(): void  { vscode.postMessage({ type: 'pickCaCert' }); }
  function pickCaKey(): void   { vscode.postMessage({ type: 'pickCaKey' }); }
  function cancel(): void      { vscode.postMessage({ type: 'cancel' }); }
  function saveCsr(): void     { vscode.postMessage({ type: 'saveCsrFile' }); }
  function saveKey(): void     { vscode.postMessage({ type: 'savePrivateKey' }); }
  function startOver(): void   { panelState = 'idle'; csrPemReady = ''; errorMsg = ''; }

  function copyCsr(): void {
    navigator.clipboard.writeText(csrPemReady).catch(() => {});
  }

  function generate(): void {
    errorMsg = validate() ?? '';
    if (errorMsg) return;

    if (isCsrMode) {
      const params: CertCreateParams = {
        cn: cn.trim(), o: o.trim(), ou: ou.trim(),
        c: c.trim(), st: st.trim(), l: l.trim(), email: email.trim(),
        dnsNames: dnsNames.trim(), ipAddresses: ipAddresses.trim(),
        keyAlgorithm,
        validityDays: Math.floor(validityDays),
        isCA,
        keyUsageDigitalSignature, keyUsageKeyEncipherment,
        keyUsageDataEncipherment, keyUsageKeyCertSign, keyUsageCRLSign,
        ekuServerAuth, ekuClientAuth, ekuCodeSigning, ekuEmailProtection,
        signingMode: 'csr',
        password: '',
      };
      vscode.postMessage({ type: 'generateCsr', params, keyPassword });
      return;
    }

    const params: CertCreateParams = {
      cn: cn.trim(), o: o.trim(), ou: ou.trim(),
      c: c.trim(), st: st.trim(), l: l.trim(), email: email.trim(),
      dnsNames: dnsNames.trim(), ipAddresses: ipAddresses.trim(),
      keyAlgorithm,
      validityDays: Math.floor(validityDays),
      isCA,
      keyUsageDigitalSignature,  keyUsageKeyEncipherment,
      keyUsageDataEncipherment,  keyUsageKeyCertSign,  keyUsageCRLSign,
      ekuServerAuth, ekuClientAuth, ekuCodeSigning, ekuEmailProtection,
      signingMode,
      password,
    };
    vscode.postMessage({ type: 'generate', params });
  }

  const ISO_COUNTRIES: [string, string][] = [
    ['', '— select —'], ['US', 'US — United States'], ['GB', 'GB — United Kingdom'],
    ['DE', 'DE — Germany'], ['FR', 'FR — France'], ['CA', 'CA — Canada'],
    ['AU', 'AU — Australia'], ['JP', 'JP — Japan'], ['CN', 'CN — China'],
    ['IN', 'IN — India'], ['BR', 'BR — Brazil'], ['NL', 'NL — Netherlands'],
    ['CH', 'CH — Switzerland'], ['SE', 'SE — Sweden'], ['NO', 'NO — Norway'],
    ['DK', 'DK — Denmark'], ['FI', 'FI — Finland'], ['ES', 'ES — Spain'],
    ['IT', 'IT — Italy'], ['PL', 'PL — Poland'], ['CZ', 'CZ — Czech Republic'],
    ['AT', 'AT — Austria'], ['BE', 'BE — Belgium'], ['IE', 'IE — Ireland'],
    ['NZ', 'NZ — New Zealand'], ['SG', 'SG — Singapore'], ['HK', 'HK — Hong Kong'],
    ['KR', 'KR — South Korea'], ['IL', 'IL — Israel'], ['ZA', 'ZA — South Africa'],
  ];
</script>

<div class="panel">
  {#if panelState === 'csrReady'}
    <!-- ── CSR ready results screen ─────────────────────────────────────── -->
    <div class="csr-ready">
      <div class="csr-ready-header">
        <span class="csr-ready-icon">✅</span>
        <div>
          <h1 class="panel-title" style="margin-bottom:4px;">Your CSR is ready</h1>
          <p class="csr-ready-subtitle">Submit the CSR to your Certificate Authority. They will return a signed certificate.</p>
        </div>
      </div>

      <section class="section">
        <div class="section-header-row">
          <h2 class="section-title" style="margin:0;">Certificate Signing Request (CSR)</h2>
          <button class="btn-secondary btn-sm" on:click={copyCsr}>Copy</button>
        </div>
        <textarea class="csr-pem" readonly rows="12" value={csrPemReady} />
        <button class="btn-secondary" style="margin-top:10px;" on:click={saveCsr}>
          ⬇ Save CSR (.csr)
        </button>
      </section>

      <section class="section">
        <h2 class="section-title">Private Key</h2>
        <p class="csr-note">
          <strong>Keep this file safe.</strong> You will need it later when your CA returns the signed certificate, to bundle both together into a P12 file.
        </p>
        <button class="btn-secondary" on:click={saveKey}>
          ⬇ Save Private Key (.key)
        </button>
      </section>

      <div class="actions">
        <button class="btn-secondary" on:click={startOver}>Start Over</button>
      </div>
    </div>

  {:else}
    <!-- ── Certificate creation form ───────────────────────────────── -->

  <!-- ── Subject ─────────────────────────────────────────────────────────── -->
  <section class="section">
    <h2 class="section-title">Subject</h2>
    <div class="grid2">
      <label class="field required">
        <span>Common Name (CN)</span>
        <input bind:value={cn} type="text" placeholder="e.g. my-service.example.com" autocomplete="off" />
      </label>
      <label class="field">
        <span>Email</span>
        <input bind:value={email} type="email" placeholder="admin@example.com" autocomplete="off" />
      </label>
      <label class="field">
        <span>Organization (O)</span>
        <input bind:value={o} type="text" placeholder="ACME Corp" autocomplete="off" />
      </label>
      <label class="field">
        <span>Org. Unit (OU)</span>
        <input bind:value={ou} type="text" placeholder="Engineering" autocomplete="off" />
      </label>
      <label class="field">
        <span>Country (C)</span>
        <select bind:value={c}>
          {#each ISO_COUNTRIES as [code, label]}
            <option value={code}>{label}</option>
          {/each}
        </select>
      </label>
      <label class="field">
        <span>State / Province (ST)</span>
        <input bind:value={st} type="text" placeholder="California" autocomplete="off" />
      </label>
      <label class="field">
        <span>Locality (L)</span>
        <input bind:value={l} type="text" placeholder="San Francisco" autocomplete="off" />
      </label>
    </div>
  </section>

  <!-- ── SANs ─────────────────────────────────────────────────────────────── -->
  <section class="section">
    <h2 class="section-title">Subject Alternative Names</h2>
    <div class="grid2">
      <label class="field">
        <span>DNS Names</span>
        <textarea bind:value={dnsNames} rows="3"
          placeholder="One per line or comma-separated&#10;e.g. example.com, www.example.com" />
      </label>
      <label class="field">
        <span>IP Addresses</span>
        <textarea bind:value={ipAddresses} rows="3"
          placeholder="One per line or comma-separated&#10;e.g. 10.0.0.1, 192.168.1.100" />
      </label>
    </div>
  </section>

  <!-- ── Key & Validity ──────────────────────────────────────────────────── -->
  <section class="section">
    <h2 class="section-title">Key &amp; Validity</h2>
    <div class="grid3">
      <label class="field">
        <span>Key Algorithm</span>
        <select bind:value={keyAlgorithm}>
          <option value="RSA-2048">RSA-2048  (recommended)</option>
          <option value="RSA-4096">RSA-4096  (stronger)</option>
          <option value="EC-P256">EC P-256  (ECDSA, fast)</option>
          <option value="EC-P384">EC P-384  (ECDSA)</option>
          <option value="EC-P521">EC P-521  (ECDSA, strongest)</option>
        </select>
      </label>
      <label class="field">
        <span>Validity (days)</span>
        <input bind:value={validityDays} type="number" min="1" max="36500" step="1" />
      </label>
      <label class="field checkbox-field" style="align-self:end;">
        <input type="checkbox" bind:checked={isCA} />
        <span>Certificate Authority (CA)</span>
      </label>
    </div>
  </section>

  <!-- ── Key Usage ───────────────────────────────────────────────────────── -->
  <section class="section">
    <h2 class="section-title">Key Usage</h2>
    <div class="checkbox-grid">
      <label class="checkbox-field">
        <input type="checkbox" bind:checked={keyUsageDigitalSignature} />
        Digital Signature
      </label>
      <label class="checkbox-field" class:disabled={isEC}>
        <input type="checkbox" bind:checked={keyUsageKeyEncipherment} disabled={isEC} />
        Key Encipherment <span class="hint">{isEC ? '(RSA only)' : ''}</span>
      </label>
      <label class="checkbox-field" class:disabled={isEC}>
        <input type="checkbox" bind:checked={keyUsageDataEncipherment} disabled={isEC} />
        Data Encipherment <span class="hint">{isEC ? '(RSA only)' : ''}</span>
      </label>
      <label class="checkbox-field">
        <input type="checkbox" bind:checked={keyUsageKeyCertSign} />
        Key Cert Sign
      </label>
      <label class="checkbox-field">
        <input type="checkbox" bind:checked={keyUsageCRLSign} />
        CRL Sign
      </label>
    </div>
  </section>

  <!-- ── Extended Key Usage ──────────────────────────────────────────────── -->
  <section class="section">
    <h2 class="section-title">Extended Key Usage</h2>
    <div class="checkbox-grid">
      <label class="checkbox-field">
        <input type="checkbox" bind:checked={ekuServerAuth} />
        TLS Server Authentication
      </label>
      <label class="checkbox-field">
        <input type="checkbox" bind:checked={ekuClientAuth} />
        TLS Client Authentication
      </label>
      <label class="checkbox-field">
        <input type="checkbox" bind:checked={ekuCodeSigning} />
        Code Signing
      </label>
      <label class="checkbox-field">
        <input type="checkbox" bind:checked={ekuEmailProtection} />
        Email Protection (S/MIME)
      </label>
    </div>
  </section>

  <!-- ── Signing ──────────────────────────────────────────────────────────── -->
  <section class="section">
    <h2 class="section-title">Signing</h2>
    <div class="radio-group">
      <label class="radio-field">
        <input type="radio" bind:group={signingMode} value="self-signed" />
        Self-signed
      </label>
      <label class="radio-field">
        <input type="radio" bind:group={signingMode} value="ca-signed" />
        Signed by a CA
      </label>
      <label class="radio-field">
        <input type="radio" bind:group={signingMode} value="csr" />
        CSR only — sign later
      </label>
    </div>

    {#if isCsrMode}
      <p class="csr-mode-hint">A Certificate Signing Request (CSR) will be generated. Submit it to a CA to obtain a signed certificate.</p>
    {/if}

    {#if signingMode === 'ca-signed'}
      <div class="ca-section">
        <div class="ca-row">
          <button class="btn-secondary" on:click={pickCaCert}>Browse CA Certificate…</button>
          {#if caCertSubject}
            <span class="ca-info">✓ {caCertSubject}</span>
          {:else}
            <span class="ca-placeholder">No certificate selected</span>
          {/if}
        </div>
        <div class="ca-row">
          <button class="btn-secondary" on:click={pickCaKey}>Browse CA Private Key…</button>
          {#if caKeyDesc}
            <span class="ca-info">✓ {caKeyDesc} key loaded</span>
          {:else}
            <span class="ca-placeholder">No key selected</span>
          {/if}
        </div>
      </div>
    {/if}
  </section>

  <!-- ── P12 Password (hidden in CSR mode) ─────────────────────────────── -->
  {#if isCsrMode}
    <section class="section">
      <h2 class="section-title">Private Key Password <span class="hint">(optional)</span></h2>
      <div class="grid2">
        <label class="field">
          <span>Password <span class="hint">(leave empty for none)</span></span>
          <input bind:value={keyPassword} type="password" autocomplete="new-password" />
        </label>
      </div>
    </section>
  {:else}
    <section class="section">
      <h2 class="section-title">P12 Password</h2>
      <div class="grid2">
        <label class="field">
          <span>Password <span class="hint">(leave empty for no password)</span></span>
          <input bind:value={password} type="password" autocomplete="new-password" />
        </label>
        <label class="field" class:error={passwordMismatch && passwordConfirm !== ''}>
          <span>Confirm Password</span>
          <input bind:value={passwordConfirm} type="password" autocomplete="new-password" />
          {#if passwordMismatch && passwordConfirm !== ''}
            <span class="field-error">Passwords do not match</span>
          {/if}
        </label>
      </div>
    </section>
  {/if}

  <!-- ── Status / Error ───────────────────────────────────────────────────── -->
  {#if errorMsg}
    <div class="banner banner-error">{errorMsg}</div>
  {/if}

  {#if panelState === 'generating'}
    <div class="banner banner-info">⏳ Generating certificate, please wait…</div>
  {/if}

  <!-- ── Actions ──────────────────────────────────────────────────────────── -->
  <div class="actions">
    <button class="btn-secondary" on:click={cancel} disabled={panelState === 'generating'}>
      Cancel
    </button>
    <button class="btn-primary" on:click={generate} disabled={panelState === 'generating'}>
      {#if panelState === 'generating'}
        {isCsrMode ? 'Generating CSR…' : 'Generating…'}
      {:else}
        {isCsrMode ? 'Generate CSR' : 'Generate Certificate'}
      {/if}
    </button>
  </div>
  {/if}
</div>

<style>
  .panel {
    max-width: 760px;
    margin: 0 auto;
    padding: 20px 24px 40px;
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size);
    color: var(--vscode-foreground);
  }

  .panel-title {
    font-size: 1.4em;
    font-weight: 600;
    margin: 0 0 20px;
    color: var(--vscode-titleBar-activeForeground, var(--vscode-foreground));
  }

  .section {
    margin-bottom: 24px;
    padding: 16px;
    background: var(--vscode-editor-background);
    border: 1px solid var(--vscode-panel-border, var(--vscode-widget-border, #444));
    border-radius: 4px;
  }

  .section-title {
    font-size: 0.9em;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--vscode-descriptionForeground);
    margin: 0 0 14px;
  }

  /* ── Form grids */
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px 16px; }
  .grid3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px 16px; }

  @media (max-width: 520px) {
    .grid2, .grid3 { grid-template-columns: 1fr; }
  }

  /* ── Fields */
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .field span { font-size: 0.85em; color: var(--vscode-input-foreground, var(--vscode-foreground)); }
  .field.required > span::after { content: ' *'; color: var(--vscode-errorForeground, #f48); }
  .field.error input { border-color: var(--vscode-errorForeground, #f48) !important; }
  .field-error { font-size: 0.8em; color: var(--vscode-errorForeground, #f48); }

  input[type="text"], input[type="email"], input[type="number"], input[type="password"],
  select, textarea {
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, var(--vscode-widget-border, #555));
    border-radius: 2px;
    padding: 5px 8px;
    font-family: inherit;
    font-size: inherit;
    outline: none;
    width: 100%;
    box-sizing: border-box;
  }
  input:focus, select:focus, textarea:focus {
    border-color: var(--vscode-focusBorder, #007fd4);
  }
  textarea { resize: vertical; }
  select { cursor: pointer; }
  input[disabled] { opacity: 0.5; cursor: not-allowed; }

  /* ── Checkboxes */
  .checkbox-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 8px;
  }
  .checkbox-field {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: 0.9em;
  }
  .checkbox-field.disabled { opacity: 0.45; cursor: not-allowed; }

  input[type="checkbox"], input[type="radio"] {
    accent-color: var(--vscode-focusBorder, #007fd4);
    cursor: pointer;
  }

  /* ── Radios */
  .radio-group { display: flex; gap: 24px; margin-bottom: 12px; }
  .radio-field { display: flex; align-items: center; gap: 8px; cursor: pointer; }

  /* ── CA section */
  .ca-section { display: flex; flex-direction: column; gap: 10px; }
  .ca-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .ca-info { font-size: 0.85em; color: var(--vscode-terminal-ansiGreen, #4ec9b0); word-break: break-all; }
  .ca-placeholder { font-size: 0.85em; color: var(--vscode-descriptionForeground); font-style: italic; }

  /* ── Banners */
  .banner {
    padding: 10px 14px;
    border-radius: 3px;
    margin-bottom: 14px;
    font-size: 0.9em;
  }
  .banner-error {
    background: color-mix(in srgb, var(--vscode-errorForeground, #f66) 15%, transparent);
    border: 1px solid var(--vscode-errorForeground, #f66);
    color: var(--vscode-errorForeground, #f66);
  }
  .banner-info {
    background: color-mix(in srgb, var(--vscode-focusBorder, #007fd4) 15%, transparent);
    border: 1px solid var(--vscode-focusBorder, #007fd4);
    color: var(--vscode-foreground);
  }

  /* ── Buttons */
  .actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 4px; }

  .btn-primary, .btn-secondary {
    padding: 7px 16px;
    border: none;
    border-radius: 2px;
    font-family: inherit;
    font-size: 0.9em;
    cursor: pointer;
    transition: opacity 0.15s;
  }
  .btn-primary:disabled, .btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

  .btn-primary {
    background: var(--vscode-button-background, #0e639c);
    color: var(--vscode-button-foreground, #fff);
  }
  .btn-primary:hover:not(:disabled) { background: var(--vscode-button-hoverBackground, #1177bb); }

  .btn-secondary {
    background: var(--vscode-button-secondaryBackground, #3a3d41);
    color: var(--vscode-button-secondaryForeground, #ccc);
  }
  .btn-secondary:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground, #45494e); }

  .hint { color: var(--vscode-descriptionForeground); font-weight: normal; }

  /* ── CSR mode */
  .csr-mode-hint {
    margin: 8px 0 0;
    font-size: 0.85em;
    color: var(--vscode-descriptionForeground);
    font-style: italic;
  }

  /* ── CSR ready screen */
  .csr-ready { padding: 0; }
  .csr-ready-header {
    display: flex;
    align-items: flex-start;
    gap: 14px;
    margin-bottom: 20px;
    padding: 16px;
    background: color-mix(in srgb, var(--vscode-focusBorder, #007fd4) 10%, transparent);
    border: 1px solid var(--vscode-focusBorder, #007fd4);
    border-radius: 4px;
  }
  .csr-ready-icon { font-size: 1.8em; line-height: 1; margin-top: 2px; }
  .csr-ready-subtitle { margin: 0; color: var(--vscode-descriptionForeground); font-size: 0.9em; }
  .section-header-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
  .csr-pem {
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.8em;
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground);
    border: 1px solid var(--vscode-input-border, #555);
    border-radius: 2px;
    padding: 8px;
    width: 100%;
    box-sizing: border-box;
    resize: vertical;
    white-space: pre;
  }
  .csr-note {
    margin: 0 0 12px;
    font-size: 0.875em;
    color: var(--vscode-descriptionForeground);
    padding: 10px 12px;
    background: color-mix(in srgb, var(--vscode-editorWarning-foreground, #cca700) 12%, transparent);
    border: 1px solid var(--vscode-editorWarning-foreground, #cca700);
    border-radius: 3px;
  }
  .btn-sm { padding: 4px 10px; font-size: 0.82em; }
</style>
