<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { Fingerprints as FP } from '../types';

  export let fingerprints: FP;

  const dispatch = createEventDispatcher<{ copy: string }>();
</script>

<div class="fps">
  <div class="fp-row">
    <div class="fp-lbl-wrap">
      <span class="fp-algo">SHA-1</span>
      <span class="fp-warn" title="SHA-1 should not be used for new certificates">⚠ weak</span>
    </div>
    <code class="fp-val">{fingerprints.sha1}</code>
    <button class="copy-btn" on:click={() => dispatch('copy', fingerprints.sha1)} title="Copy SHA-1">⧉ Copy</button>
  </div>

  <div class="fp-row">
    <div class="fp-lbl-wrap">
      <span class="fp-algo">SHA-256</span>
    </div>
    <code class="fp-val">{fingerprints.sha256}</code>
    <button class="copy-btn" on:click={() => dispatch('copy', fingerprints.sha256)} title="Copy SHA-256">⧉ Copy</button>
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
</style>
