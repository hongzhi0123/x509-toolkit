<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  /** Colon-separated hex string, e.g. "AB:CD:EF:..." */
  export let value: string;
  /** Number of byte groups to show before truncating */
  export let previewBytes: number = 24;

  const dispatch = createEventDispatcher<{ copy: void }>();

  let expanded = false;

  $: bytes = value.split(':');
  $: preview = bytes.slice(0, previewBytes).join(':');
  $: overflow = bytes.slice(previewBytes);
  $: tooLong = bytes.length > previewBytes;
</script>

<div class="hex-block">
  <div class="hex-toolbar">
    <span class="hex-count">{bytes.length} bytes</span>
    <button class="copy-btn" on:click={() => dispatch('copy')} title="Copy hex">⧉ Copy</button>
  </div>
  <pre class="hex-content">{preview}{#if tooLong && !expanded}<span class="ellipsis"> …</span>{:else if tooLong}:{overflow.join(':')}{/if}</pre>
  {#if tooLong}
    <button class="expand-btn" on:click={() => (expanded = !expanded)}>
      {expanded ? 'Show less' : `Show all ${bytes.length} bytes`}
    </button>
  {/if}
</div>

<style>
  .hex-block { display: flex; flex-direction: column; gap: 0.22rem; }

  .hex-toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.5rem;
  }

  .hex-count {
    font-size: 0.66rem;
    color: var(--vscode-descriptionForeground, #888);
  }

  .hex-content {
    margin: 0;
    padding: 0.4rem 0.55rem;
    font-family: var(--vscode-editor-font-family, 'Courier New', monospace);
    font-size: 0.7rem;
    white-space: pre-wrap;
    word-break: break-all;
    color: var(--vscode-editor-foreground);
    background: var(--vscode-input-background, rgba(0,0,0,0.18));
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.08));
    border-radius: 4px;
    line-height: 1.7;
  }

  .ellipsis {
    color: var(--vscode-descriptionForeground, #888);
    font-style: italic;
  }

  .expand-btn {
    background: none;
    border: none;
    color: var(--vscode-textLink-foreground, #89b4fa);
    cursor: pointer;
    font-size: 0.7rem;
    font-family: var(--vscode-font-family);
    text-decoration: underline;
    text-align: left;
    padding: 0;
  }
  .expand-btn:hover { color: var(--vscode-textLink-activeForeground, #b4c7f8); }
</style>
