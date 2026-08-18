<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { CertExtension } from '../types';

  export let extensions: CertExtension[];
  export let loadingUrls: Set<string> = new Set();

  const dispatch = createEventDispatcher<{ copy: string; loadCaIssuer: string }>();

  let expanded: Set<number> = new Set();
  let rawExpanded: Set<number> = new Set();

  function toggle(i: number): void {
    if (expanded.has(i)) { expanded.delete(i); }
    else { expanded.add(i); }
    expanded = expanded; // reactivity trigger
  }

  function toggleRaw(i: number): void {
    if (rawExpanded.has(i)) { rawExpanded.delete(i); }
    else { rawExpanded.add(i); }
    rawExpanded = rawExpanded; // reactivity trigger
  }

  function hasDecoded(ext: CertExtension): boolean {
    return !!ext.value && ext.value !== '(see raw hex)' && ext.value !== '(parse error — see raw hex)';
  }
</script>

<div class="ext-list">
  {#each extensions as ext, i}
    <div class="ext-item" class:critical={ext.critical}>
      <button class="ext-hdr" on:click={() => toggle(i)}>
        <span class="ext-left">
          <span
            class="ext-chev"
            style="transform: rotate({expanded.has(i) ? '270deg' : '90deg'})"
          >›</span>
          <span class="ext-name">{ext.name}</span>
          {#if ext.critical}
            <span class="crit-badge">Critical</span>
          {/if}
        </span>
        <span class="ext-oid">{ext.oid}</span>
      </button>

      {#if expanded.has(i)}
        <div class="ext-body">
          {#if hasDecoded(ext)}
            <div class="ext-field">
              <div class="ext-field-hdr">
                <span class="ext-flbl">Value</span>
                <button class="copy-btn" on:click={() => dispatch('copy', ext.value)}>⧉ Copy</button>
              </div>
              <pre class="ext-val">{ext.value}</pre>
            </div>
          {/if}

          {#if ext.caIssuerUrls && ext.caIssuerUrls.length > 0}
            <div class="ext-field">
              <span class="ext-flbl">CA Issuer Certificates</span>
              {#each ext.caIssuerUrls as url}
                <div class="ca-issuer-row">
                  <span class="ca-issuer-url" title={url}>{url}</span>
                  <button
                    class="load-ca-btn"
                    disabled={loadingUrls.has(url)}
                    on:click={() => dispatch('loadCaIssuer', url)}
                  >
                    {#if loadingUrls.has(url)}
                      <span class="load-spinner"></span> Loading…
                    {:else}
                      ↓ Load
                    {/if}
                  </button>
                </div>
              {/each}
            </div>
          {/if}

          {#if hasDecoded(ext)}
            <div class="ext-field">
              <button class="raw-toggle" on:click={() => toggleRaw(i)}>
                <span class="raw-chev" style="transform: rotate({rawExpanded.has(i) ? '270deg' : '90deg'})">›</span>
                Raw (DER hex)
              </button>
              {#if rawExpanded.has(i)}
                <div class="ext-field-hdr">
                  <span></span>
                  <button class="copy-btn" on:click={() => dispatch('copy', ext.raw)}>⧉ Copy</button>
                </div>
                <pre class="ext-raw">{ext.raw}</pre>
              {/if}
            </div>
          {:else}
            <div class="ext-field">
              <div class="ext-field-hdr">
                <span class="ext-flbl">Raw (DER hex)</span>
                <button class="copy-btn" on:click={() => dispatch('copy', ext.raw)}>⧉ Copy</button>
              </div>
              <pre class="ext-raw">{ext.raw}</pre>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  {/each}
</div>

<style>
  .ext-list { display: flex; flex-direction: column; }

  .ext-item {
    border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.05));
  }
  .ext-item:last-child { border-bottom: none; }

  .ext-item.critical .ext-hdr { border-left: 3px solid rgba(243,139,168,0.5); }

  .ext-hdr {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 0.38rem 0.7rem;
    background: none;
    border: none;
    border-left: 3px solid transparent;
    cursor: pointer;
    color: var(--vscode-editor-foreground);
    font-family: var(--vscode-font-family);
    font-size: 0.8rem;
    text-align: left;
    transition: background 0.1s;
    gap: 0.5rem;
  }
  .ext-hdr:hover { background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.04)); }

  .ext-left {
    display: flex;
    align-items: center;
    gap: 0.38rem;
    min-width: 0;
    flex: 1;
  }

  .ext-chev {
    font-size: 0.83rem;
    color: var(--vscode-descriptionForeground, #888);
    display: inline-block;
    transition: transform 0.16s ease;
    flex-shrink: 0;
    line-height: 1;
  }

  .ext-name {
    font-weight: 500;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .crit-badge {
    display: inline-block;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.6rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    background: rgba(243,139,168,0.12);
    color: #f38ba8;
    border: 1px solid rgba(243,139,168,0.28);
    text-transform: uppercase;
    flex-shrink: 0;
  }

  .ext-oid {
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.68rem;
    color: var(--vscode-descriptionForeground, #888);
    flex-shrink: 0;
  }

  .ext-body {
    padding: 0.45rem 0.7rem 0.65rem 1.7rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    background: var(--vscode-input-background, rgba(0,0,0,0.1));
  }

  .ext-field { display: flex; flex-direction: column; gap: 0.22rem; }

  .raw-toggle {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    background: none;
    border: none;
    cursor: pointer;
    color: var(--vscode-descriptionForeground, #888);
    font-family: var(--vscode-font-family);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
    padding: 0;
  }
  .raw-toggle:hover { color: var(--vscode-editor-foreground); }

  .raw-chev {
    font-size: 0.83rem;
    display: inline-block;
    transition: transform 0.16s ease;
    line-height: 1;
  }

  .ext-field-hdr {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .ext-flbl {
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--vscode-descriptionForeground, #888);
    font-weight: 600;
  }

  .ext-val,
  .ext-raw {
    margin: 0;
    padding: 0.38rem 0.5rem;
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.7rem;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--vscode-editor-foreground);
    background: var(--vscode-input-background, rgba(0,0,0,0.15));
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.08));
    border-radius: 4px;
    max-height: 180px;
    overflow-y: auto;
  }

  /* ─── CA Issuer download rows ─── */
  .ca-issuer-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.3rem 0;
  }

  .ca-issuer-url {
    flex: 1;
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.7rem;
    color: var(--vscode-textLink-foreground, #89b4fa);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .load-ca-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.2rem 0.55rem;
    background: var(--vscode-button-background, #7c3aed);
    color: var(--vscode-button-foreground, #fff);
    border: none;
    border-radius: 3px;
    cursor: pointer;
    font-size: 0.72rem;
    font-family: var(--vscode-font-family);
    white-space: nowrap;
    flex-shrink: 0;
    transition: opacity 0.12s;
  }
  .load-ca-btn:hover:not(:disabled) { opacity: 0.85; }
  .load-ca-btn:disabled { opacity: 0.5; cursor: default; }

  .load-spinner {
    display: inline-block;
    width: 10px; height: 10px;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
