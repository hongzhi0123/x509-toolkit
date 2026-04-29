<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let label: string;
  export let value: string;
  export let copyable: boolean = false;
  export let mono: boolean = false;

  const dispatch = createEventDispatcher<{ copy: void }>();
</script>

<div class="field-row">
  <span class="fl">{label}</span>
  <span class="fv" class:mono>{value}</span>
  {#if copyable}
    <button class="copy-btn" on:click={() => dispatch('copy')} title="Copy">⧉</button>
  {/if}
</div>

<style>
  .field-row {
    display: grid;
    grid-template-columns: 155px 1fr auto;
    align-items: baseline;
    padding: 0.28rem 0.7rem;
    gap: 0.5rem;
    border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.04));
  }

  .field-row:last-child { border-bottom: none; }

  .field-row:hover {
    background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.03));
  }

  .fl {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--vscode-descriptionForeground, #888);
    font-weight: 600;
    white-space: nowrap;
  }

  .fv {
    font-size: 0.82rem;
    color: var(--vscode-editor-foreground);
    word-break: break-word;
  }

  .fv.mono {
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.76rem;
  }
</style>
