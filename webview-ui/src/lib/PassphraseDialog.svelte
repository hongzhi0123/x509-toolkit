<script lang="ts">
  import { createEventDispatcher, onMount, tick } from 'svelte';

  export let fileName: string = 'private key';

  const dispatch = createEventDispatcher<{ submit: string; cancel: void }>();

  let passphrase = '';
  let showPassword = false;
  let inputEl: HTMLInputElement;

  onMount(() => {
    inputEl?.focus();
  });

  function submit() {
    dispatch('submit', passphrase);
    passphrase = '';
  }

  function cancel() {
    passphrase = '';
    dispatch('cancel');
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') { e.preventDefault(); submit(); }
    if (e.key === 'Escape') { e.preventDefault(); cancel(); }
  }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
<div class="backdrop" on:click|self={cancel}>
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="dialog" role="dialog" aria-modal="true" aria-labelledby="pp-title" on:keydown={handleKeydown}>
    <div class="dialog-header">
      <span class="lock-icon">🔒</span>
      <h2 id="pp-title">Encrypted Private Key</h2>
    </div>

    <p class="dialog-desc">
      <span class="file-name">{fileName}</span> is password-protected.
      Enter the passphrase to decrypt it.
    </p>

    <div class="input-row">
      <div class="input-wrap">
        {#if showPassword}
          <input
            bind:this={inputEl}
            bind:value={passphrase}
            type="text"
            class="passphrase-input"
            placeholder="Passphrase"
            autocomplete="off"
            spellcheck="false"
          />
        {:else}
          <input
            bind:this={inputEl}
            bind:value={passphrase}
            type="password"
            class="passphrase-input"
            placeholder="Passphrase"
            autocomplete="off"
            spellcheck="false"
          />
        {/if}
        <button
          class="reveal-btn"
          type="button"
          title={showPassword ? 'Hide passphrase' : 'Show passphrase'}
          on:click={async () => { showPassword = !showPassword; await tick(); inputEl?.focus(); }}
          tabindex="-1"
        >
          {showPassword ? '🙈' : '👁'}
        </button>
      </div>
    </div>

    <div class="dialog-footer">
      <button class="btn btn-cancel" type="button" on:click={cancel}>Cancel</button>
      <button class="btn btn-ok" type="button" on:click={submit}>Decrypt</button>
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    z-index: 1000;
    background: rgba(0, 0, 0, 0.6);
    backdrop-filter: blur(3px);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.5rem;
    animation: fade-in 0.12s ease;
  }

  @keyframes fade-in {
    from { opacity: 0; }
    to   { opacity: 1; }
  }

  .dialog {
    background: var(--vscode-editorWidget-background, #252537);
    border: 1px solid var(--vscode-focusBorder, rgba(255,255,255,0.2));
    border-radius: 8px;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.55);
    width: 100%;
    max-width: 400px;
    padding: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    animation: slide-up 0.15s ease;
  }

  @keyframes slide-up {
    from { transform: translateY(12px); opacity: 0; }
    to   { transform: translateY(0);    opacity: 1; }
  }

  .dialog-header {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .lock-icon {
    font-size: 1.4rem;
    line-height: 1;
  }

  h2 {
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--vscode-editor-foreground);
  }

  .dialog-desc {
    margin: 0;
    font-size: 0.82rem;
    color: var(--vscode-descriptionForeground, #aaa);
    line-height: 1.5;
  }

  .file-name {
    font-style: italic;
    color: var(--vscode-editor-foreground);
  }

  .input-row {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
  }

  .input-wrap {
    position: relative;
    display: flex;
    align-items: center;
  }

  .passphrase-input {
    width: 100%;
    padding: 0.5rem 2.4rem 0.5rem 0.65rem;
    background: var(--vscode-input-background, rgba(0,0,0,0.25));
    color: var(--vscode-input-foreground, var(--vscode-editor-foreground));
    border: 1px solid var(--vscode-input-border, rgba(255,255,255,0.15));
    border-radius: 4px;
    font-size: 0.88rem;
    font-family: var(--vscode-font-family);
    outline: none;
    box-sizing: border-box;
    transition: border-color 0.15s;
  }

  .passphrase-input:focus {
    border-color: var(--vscode-focusBorder, #569cd6);
  }

  .reveal-btn {
    position: absolute;
    right: 0.4rem;
    background: none;
    border: none;
    cursor: pointer;
    padding: 0;
    font-size: 0.9rem;
    color: var(--vscode-descriptionForeground, #888);
    line-height: 1;
    display: flex;
    align-items: center;
  }

  .reveal-btn:hover {
    color: var(--vscode-editor-foreground);
  }

  .dialog-footer {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 0.25rem;
  }

  .btn {
    padding: 0.38rem 1.1rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-family: var(--vscode-font-family);
    cursor: pointer;
    border: 1px solid transparent;
    transition: background 0.12s, border-color 0.12s;
    white-space: nowrap;
  }

  .btn-cancel {
    background: var(--vscode-button-secondaryBackground, rgba(255,255,255,0.07));
    color: var(--vscode-button-secondaryForeground, var(--vscode-editor-foreground));
    border-color: var(--vscode-panel-border, rgba(255,255,255,0.12));
  }

  .btn-cancel:hover {
    background: var(--vscode-button-secondaryHoverBackground, rgba(255,255,255,0.12));
  }

  .btn-ok {
    background: var(--vscode-button-background, #0e639c);
    color: var(--vscode-button-foreground, #fff);
    border-color: transparent;
    font-weight: 600;
  }

  .btn-ok:hover {
    background: var(--vscode-button-hoverBackground, #1177bb);
  }
</style>
