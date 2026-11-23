<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { Fingerprints as FP } from '../types';
  import { formatHexValue, getAvailableFormats, modeBadgeText, nextValueMode } from './valueFormat';
  import type { ValueMode } from './valueFormat';

  export let fingerprints: FP;

  const dispatch = createEventDispatcher<{ copy: string }>();

  let sha1Mode: ValueMode = 'hex';
  let sha256Mode: ValueMode = 'hex';

  $: sha1Modes = getAvailableFormats(fingerprints.sha1);
  $: sha256Modes = getAvailableFormats(fingerprints.sha256);
  $: sha1Mode = sha1Modes.includes(sha1Mode) ? sha1Mode : (sha1Modes[0] ?? 'hex');
  $: sha256Mode = sha256Modes.includes(sha256Mode) ? sha256Mode : (sha256Modes[0] ?? 'hex');
  $: sha1Display = formatHexValue(fingerprints.sha1, sha1Mode) ?? fingerprints.sha1;
  $: sha256Display = formatHexValue(fingerprints.sha256, sha256Mode) ?? fingerprints.sha256;
</script>

<div class="fps">
  <div class="fp-row">
    <div class="fp-lbl-wrap">
      <span class="fp-algo">SHA-1</span>
      <span class="fp-warn" title="SHA-1 should not be used for new certificates">⚠ weak</span>
    </div>
    <code class="fp-val">{sha1Display}</code>
    <div class="fp-actions">
      {#if sha1Modes.length > 1}
        <button
          class="copy-btn fp-toggle-btn"
          on:click={() => sha1Mode = nextValueMode(sha1Mode, sha1Modes)}
          title="Toggle SHA-1 format (hex/decimal/base64)"
          aria-label="Toggle SHA-1 fingerprint format"
        >{modeBadgeText(sha1Mode)}</button>
      {/if}
      <button class="copy-btn" on:click={() => dispatch('copy', sha1Display)} title="Copy SHA-1">⧉</button>
    </div>
  </div>

  <div class="fp-row">
    <div class="fp-lbl-wrap">
      <span class="fp-algo">SHA-256</span>
    </div>
    <code class="fp-val">{sha256Display}</code>
    <div class="fp-actions">
      {#if sha256Modes.length > 1}
        <button
          class="copy-btn fp-toggle-btn"
          on:click={() => sha256Mode = nextValueMode(sha256Mode, sha256Modes)}
          title="Toggle SHA-256 format (hex/decimal/base64)"
          aria-label="Toggle SHA-256 fingerprint format"
        >{modeBadgeText(sha256Mode)}</button>
      {/if}
      <button class="copy-btn" on:click={() => dispatch('copy', sha256Display)} title="Copy SHA-256">⧉</button>
    </div>
  </div>
</div>

<style>
  .fps { display: flex; flex-direction: column; }

  .fp-row {
    display: grid;
    grid-template-columns: 80px 1fr auto;
    align-items: center;
    padding: 0.42rem 0.7rem;
    gap: 0.5rem;
    border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.05));
  }
  .fp-row:last-child { border-bottom: none; }
  .fp-row:hover { background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.03)); }

  .fp-lbl-wrap {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .fp-algo {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 700;
    color: var(--vscode-descriptionForeground, #888);
  }

  .fp-warn {
    font-size: 0.6rem;
    color: #f9e2af;
    font-weight: 600;
  }

  .fp-val {
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.7rem;
    color: var(--vscode-editor-foreground);
    word-break: break-all;
    background: none;
    border: none;
    padding: 0;
  }

  .fp-actions {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
  }

  .fp-toggle-btn {
    padding-left: 0.42rem;
    padding-right: 0.42rem;
  }
</style>
