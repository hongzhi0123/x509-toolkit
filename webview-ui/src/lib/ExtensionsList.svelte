<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { CertExtension } from '../types';

  export let extensions: CertExtension[];

  const dispatch = createEventDispatcher<{ copy: string }>();

  let expanded: Set<number> = new Set();

  function toggle(i: number): void {
    if (expanded.has(i)) { expanded.delete(i); }
    else { expanded.add(i); }
    expanded = expanded; // reactivity trigger
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
          {#if ext.value && ext.value !== '(see raw hex)' && ext.value !== '(parse error — see raw hex)'}
            <div class="ext-field">
              <div class="ext-field-hdr">
                <span class="ext-flbl">Value</span>
                <button class="copy-btn" on:click={() => dispatch('copy', ext.value)}>⧉ Copy</button>
              </div>
              <pre class="ext-val">{ext.value}</pre>
            </div>
          {/if}

          <div class="ext-field">
            <div class="ext-field-hdr">
              <span class="ext-flbl">Raw (DER hex)</span>
              <button class="copy-btn" on:click={() => dispatch('copy', ext.raw)}>⧉ Copy</button>
            </div>
            <pre class="ext-raw">{ext.raw}</pre>
          </div>
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
</style>
