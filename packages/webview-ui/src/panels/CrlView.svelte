<script lang="ts">
  import { onMount } from 'svelte';
  import type { CrlData, CrlViewerToExtMsg, ExtToCrlViewerMsg } from '../types';
  import SectionCard from '../lib/SectionCard.svelte';
  import FieldRow from '../lib/FieldRow.svelte';
  import HexValue from '../lib/HexValue.svelte';

  const vscode = acquireVsCodeApi();

  type State = 'idle' | 'loading' | 'ready' | 'error';
  let state: State = 'idle';
  let crl: CrlData | null = null;
  let errorMessage = '';

  // Pagination for the revoked-entries list
  const PAGE_SIZE = 100;
  let page = 0;
  $: totalPages = crl ? Math.max(1, Math.ceil(crl.revokedCertificates.length / PAGE_SIZE)) : 1;
  $: pageEntries = crl
    ? crl.revokedCertificates.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
    : [];

  function copyText(value: string): void {
    const msg: CrlViewerToExtMsg = { type: 'copyToClipboard', value };
    vscode.postMessage(msg);
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        timeZoneName: 'short',
      });
    } catch {
      return iso;
    }
  }

  function reasonLabel(reason: string): string {
    const MAP: Record<string, string> = {
      unspecified: 'Unspecified',
      keyCompromise: 'Key Compromise',
      cACompromise: 'CA Compromise',
      affiliationChanged: 'Affiliation Changed',
      superseded: 'Superseded',
      cessationOfOperation: 'Cessation of Operation',
      certificateHold: 'Certificate Hold',
      removeFromCRL: 'Remove from CRL',
      privilegeWithdrawn: 'Privilege Withdrawn',
      aACompromise: 'AA Compromise',
    };
    return MAP[reason] ?? reason;
  }

  onMount(() => {
    window.addEventListener('message', (event: MessageEvent<ExtToCrlViewerMsg>) => {
      const msg = event.data;
      switch (msg.type) {
        case 'crlLoading':
          state = 'loading';
          crl = null;
          errorMessage = '';
          page = 0;
          break;
        case 'crlData':
          crl = msg.crl;
          page = 0;
          state = 'ready';
          break;
        case 'crlError':
          errorMessage = msg.message;
          state = 'error';
          break;
      }
    });

    const ready: CrlViewerToExtMsg = { type: 'crlViewerReady' };
    vscode.postMessage(ready);
  });
</script>

<!-- ── Loading ───────────────────────────────────────────────────────────── -->
{#if state === 'loading'}
  <div class="center-msg">
    <div class="spinner"></div>
    <p>Parsing CRL…</p>
  </div>

<!-- ── Error ────────────────────────────────────────────────────────────── -->
{:else if state === 'error'}
  <div class="center-msg error-msg">
    <div class="error-icon">⚠</div>
    <p>{errorMessage}</p>
  </div>

<!-- ── Idle ─────────────────────────────────────────────────────────────── -->
{:else if state === 'idle'}
  <div class="center-msg idle-msg">
    <p>No CRL loaded.</p>
  </div>

<!-- ── Ready ────────────────────────────────────────────────────────────── -->
{:else if state === 'ready' && crl}
  <div class="crl-view">

    <!-- ── Hero header ── -->
    <header class="crl-header">
      <div class="crl-header-left">
        <div class="crl-icon">📋</div>
        <div class="crl-title">
          <h1 class="crl-cn">{crl.issuer.commonName ?? crl.issuer.organization ?? crl.issuer.raw}</h1>
          <div class="crl-badges">
            <span class="meta-badge crl-tag">CRL v{crl.version}</span>
            {#if crl.isExpired}
              <span class="meta-badge expired">Expired</span>
            {:else}
              <span class="meta-badge valid">Current</span>
            {/if}
            <span class="meta-badge format-tag">{(crl.sourceFormat ?? 'unknown').toUpperCase()}</span>
          </div>
        </div>
      </div>
      <div class="crl-header-right">
        <div class="revoked-count">
          <span class="count-number">{crl.revokedCertificates.length.toLocaleString()}</span>
          <span class="count-label">revoked cert{crl.revokedCertificates.length !== 1 ? 's' : ''}</span>
        </div>
      </div>
    </header>

    <!-- ── Summary bar ── -->
    <div class="summary-bar">
      <div class="sum-item">
        <span class="sum-lbl">This Update</span>
        <span class="sum-val">{formatDate(crl.thisUpdate)}</span>
      </div>
      {#if crl.nextUpdate}
        <div class="sum-item">
          <span class="sum-lbl">Next Update</span>
          <span class="sum-val {crl.isExpired ? 'expired-text' : ''}">{formatDate(crl.nextUpdate)}</span>
        </div>
      {/if}
      <div class="sum-item">
        <span class="sum-lbl">Algorithm</span>
        <span class="sum-val">{crl.signatureAlgorithm}</span>
      </div>
      {#if crl.crlNumber !== undefined}
        <div class="sum-item">
          <span class="sum-lbl">CRL Number</span>
          <span class="sum-val">{crl.crlNumber}</span>
        </div>
      {/if}
    </div>

    <!-- ── Issuer ── -->
    <SectionCard title="Issuer" defaultOpen={true}>
      <FieldRow label="Common Name" value={crl.issuer.commonName ?? '—'} on:copy={e => copyText(e.detail)} />
      {#if crl.issuer.organization}
        <FieldRow label="Organization" value={crl.issuer.organization} on:copy={e => copyText(e.detail)} />
      {/if}
      {#if crl.issuer.organizationalUnit}
        <FieldRow label="Org. Unit" value={crl.issuer.organizationalUnit} on:copy={e => copyText(e.detail)} />
      {/if}
      {#if crl.issuer.country}
        <FieldRow label="Country" value={crl.issuer.country} on:copy={e => copyText(e.detail)} />
      {/if}
      {#if crl.issuer.state}
        <FieldRow label="State / Province" value={crl.issuer.state} on:copy={e => copyText(e.detail)} />
      {/if}
      {#if crl.issuer.locality}
        <FieldRow label="Locality" value={crl.issuer.locality} on:copy={e => copyText(e.detail)} />
      {/if}
      <FieldRow label="DN (raw)" value={crl.issuer.raw} on:copy={e => copyText(e.detail)} />
    </SectionCard>

    <!-- ── Validity ── -->
    <SectionCard title="Validity" defaultOpen={true}>
      <FieldRow label="This Update" value={formatDate(crl.thisUpdate)} on:copy={e => copyText(e.detail)} />
      {#if crl.nextUpdate}
        <FieldRow label="Next Update" value={formatDate(crl.nextUpdate)} on:copy={e => copyText(e.detail)} />
      {:else}
        <FieldRow label="Next Update" value="Not specified" />
      {/if}
      {#if crl.isExpired}
        <div class="expired-warning">⚠ This CRL has passed its Next Update date and may be stale.</div>
      {/if}
    </SectionCard>

    <!-- ── Details ── -->
    <SectionCard title="Details" defaultOpen={true}>
      <FieldRow label="Signature Algorithm" value={crl.signatureAlgorithm} on:copy={e => copyText(e.detail)} />
      {#if crl.crlNumber !== undefined}
        <FieldRow label="CRL Number" value={crl.crlNumber} on:copy={e => copyText(e.detail)} />
      {/if}
      {#if crl.authorityKeyIdentifier}
        <div class="field-row-hex">
          <span class="field-label">Authority Key ID</span>
          <HexValue value={crl.authorityKeyIdentifier} on:copy={e => copyText(e.detail)} />
        </div>
      {/if}
      {#if crl.issuingDistributionPoints && crl.issuingDistributionPoints.length > 0}
        <FieldRow label="Issuing Dist. Point" value={crl.issuingDistributionPoints.join('\n')} on:copy={e => copyText(e.detail)} />
      {/if}
    </SectionCard>

    <!-- ── Revoked Certificates ── -->
    <SectionCard title="Revoked Certificates ({crl.revokedCertificates.length.toLocaleString()})" defaultOpen={true}>
      {#if crl.revokedCertificates.length === 0}
        <p class="empty-list">No certificates have been revoked in this CRL.</p>
      {:else}
        {#if totalPages > 1}
          <div class="pagination">
            <button class="page-btn" disabled={page === 0} on:click={() => page--}>← Prev</button>
            <span class="page-info">Page {page + 1} / {totalPages} ({crl.revokedCertificates.length.toLocaleString()} entries)</span>
            <button class="page-btn" disabled={page >= totalPages - 1} on:click={() => page++}>Next →</button>
          </div>
        {/if}

        <table class="revoked-table">
          <thead>
            <tr>
              <th>Serial Number</th>
              <th>Revocation Date</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {#each pageEntries as entry}
              <tr>
                <td class="serial-cell">
                  <span class="serial-val">{entry.serialNumber}</span>
                  <button class="copy-btn-inline" title="Copy serial number"
                    on:click={() => copyText(entry.serialNumber)}>⎘</button>
                </td>
                <td class="date-cell">{formatDate(entry.revocationDate)}</td>
                <td class="reason-cell">
                  {#if entry.reason}
                    <span class="reason-badge reason-{entry.reason.toLowerCase()}">{reasonLabel(entry.reason)}</span>
                  {:else}
                    <span class="reason-unspecified">—</span>
                  {/if}
                  {#if entry.invalidityDate}
                    <div class="invalidity-date">Invalidity: {formatDate(entry.invalidityDate)}</div>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>

        {#if totalPages > 1}
          <div class="pagination pagination-bottom">
            <button class="page-btn" disabled={page === 0} on:click={() => page--}>← Prev</button>
            <span class="page-info">Page {page + 1} / {totalPages}</span>
            <button class="page-btn" disabled={page >= totalPages - 1} on:click={() => page++}>Next →</button>
          </div>
        {/if}
      {/if}
    </SectionCard>

    <!-- ── Raw PEM ── -->
    <SectionCard title="Raw CRL (PEM)" defaultOpen={false}>
      <div class="raw-pem-container">
        <button class="export-btn" on:click={() => copyText(crl.raw)}>⎘ Copy PEM</button>
        <pre class="raw-pem">{crl.raw}</pre>
      </div>
    </SectionCard>

  </div>
{/if}

<style>
  .crl-view {
    font-family: var(--vscode-font-family, sans-serif);
    font-size: var(--vscode-font-size, 13px);
    color: var(--vscode-foreground);
    max-width: 960px;
    margin: 0 auto;
    padding: 0 0 48px 0;
  }

  /* ── Header ── */
  .crl-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 20px 20px 16px;
    background: var(--vscode-editor-background);
    border-bottom: 1px solid var(--vscode-panel-border, #555);
  }
  .crl-header-left { display: flex; align-items: flex-start; gap: 12px; }
  .crl-icon { font-size: 2rem; line-height: 1; }
  .crl-cn {
    margin: 0 0 4px;
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--vscode-foreground);
    word-break: break-all;
  }
  .crl-badges { display: flex; flex-wrap: wrap; gap: 6px; }
  .meta-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .crl-tag { background: #1a3a5c; color: #7db6f0; }
  .valid { background: #1a3d1a; color: #6cbe6c; }
  .expired { background: #3d1a1a; color: #e87070; }
  .format-tag { background: #2a2a1a; color: #c8b76a; }

  .crl-header-right { flex-shrink: 0; text-align: right; }
  .revoked-count { display: flex; flex-direction: column; align-items: flex-end; }
  .count-number { font-size: 1.8rem; font-weight: 700; color: var(--vscode-foreground); line-height: 1; }
  .count-label { font-size: 0.75rem; color: var(--vscode-descriptionForeground); }

  /* ── Summary bar ── */
  .summary-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 0;
    border-bottom: 1px solid var(--vscode-panel-border, #555);
    background: var(--vscode-sideBar-background, #252526);
  }
  .sum-item {
    display: flex;
    flex-direction: column;
    padding: 10px 20px;
    border-right: 1px solid var(--vscode-panel-border, #444);
    min-width: 160px;
  }
  .sum-lbl { font-size: 0.7rem; text-transform: uppercase; color: var(--vscode-descriptionForeground); letter-spacing: 0.05em; margin-bottom: 2px; }
  .sum-val { font-size: 0.85rem; font-weight: 500; color: var(--vscode-foreground); }
  .expired-text { color: #e87070; }

  /* ── Revoked table ── */
  .revoked-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
  }
  .revoked-table thead th {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 2px solid var(--vscode-panel-border, #444);
    color: var(--vscode-descriptionForeground);
    font-weight: 600;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    background: var(--vscode-sideBar-background);
  }
  .revoked-table tbody tr:hover {
    background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.04));
  }
  .revoked-table td {
    padding: 7px 10px;
    border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.15));
    vertical-align: top;
  }
  .serial-cell { font-family: var(--vscode-editor-font-family, monospace); white-space: nowrap; }
  .serial-val { font-size: 0.82rem; color: var(--vscode-foreground); }
  .date-cell { white-space: nowrap; color: var(--vscode-foreground); }
  .reason-cell { }

  .reason-badge {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 8px;
    font-size: 0.72rem;
    font-weight: 500;
    background: var(--vscode-badge-background, #333);
    color: var(--vscode-badge-foreground, #ccc);
  }
  .reason-keycompromise, .reason-cacompromise { background: #3d1a1a; color: #e87070; }
  .reason-unspecified { color: var(--vscode-descriptionForeground); }
  .invalidity-date { font-size: 0.72rem; color: var(--vscode-descriptionForeground); margin-top: 2px; }

  .copy-btn-inline {
    display: inline-block;
    margin-left: 6px;
    padding: 1px 4px;
    font-size: 0.72rem;
    background: none;
    border: 1px solid var(--vscode-panel-border, #555);
    border-radius: 3px;
    color: var(--vscode-descriptionForeground);
    cursor: pointer;
    opacity: 0.5;
    transition: opacity 0.1s;
  }
  .copy-btn-inline:hover { opacity: 1; }

  /* ── Pagination ── */
  .pagination {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 4px;
  }
  .pagination-bottom { padding-top: 12px; }
  .page-btn {
    padding: 4px 12px;
    background: var(--vscode-button-secondaryBackground, #3a3d41);
    color: var(--vscode-button-secondaryForeground, #ccc);
    border: none;
    border-radius: 3px;
    cursor: pointer;
    font-size: 0.82rem;
  }
  .page-btn:disabled { opacity: 0.4; cursor: default; }
  .page-btn:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground, #45494e); }
  .page-info { color: var(--vscode-descriptionForeground); font-size: 0.82rem; }

  /* ── Raw PEM ── */
  .raw-pem-container { display: flex; flex-direction: column; gap: 8px; }
  .raw-pem {
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.78rem;
    white-space: pre-wrap;
    word-break: break-all;
    background: var(--vscode-textBlockQuote-background, #1e1e1e);
    padding: 12px;
    border-radius: 4px;
    border: 1px solid var(--vscode-panel-border, #444);
    color: var(--vscode-foreground);
    max-height: 300px;
    overflow-y: auto;
  }
  .export-btn {
    align-self: flex-start;
    padding: 5px 14px;
    font-size: 0.82rem;
    background: var(--vscode-button-secondaryBackground, #3a3d41);
    color: var(--vscode-button-secondaryForeground, #ccc);
    border: none;
    border-radius: 3px;
    cursor: pointer;
  }
  .export-btn:hover { background: var(--vscode-button-secondaryHoverBackground, #45494e); }

  /* ── Misc ── */
  .field-row-hex {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px solid var(--vscode-panel-border, rgba(128,128,128,0.12));
  }
  .field-label {
    flex: 0 0 160px;
    font-size: 0.78rem;
    color: var(--vscode-descriptionForeground);
    padding-top: 2px;
  }
  .empty-list { color: var(--vscode-descriptionForeground); font-style: italic; padding: 12px 0; }
  .expired-warning {
    padding: 10px 14px;
    margin: 8px 0;
    background: rgba(200, 0, 0, 0.1);
    border-left: 3px solid #e87070;
    border-radius: 3px;
    color: #e87070;
    font-size: 0.85rem;
  }

  /* ── Center states ── */
  .center-msg {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 200px;
    gap: 12px;
    color: var(--vscode-descriptionForeground);
  }
  .error-msg { color: var(--vscode-errorForeground, #f48771); }
  .error-icon { font-size: 2rem; }
  .idle-msg { opacity: 0.6; }
  .spinner {
    width: 28px; height: 28px;
    border: 3px solid var(--vscode-panel-border, #555);
    border-top-color: var(--vscode-progressBar-background, #007acc);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
