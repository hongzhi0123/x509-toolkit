<script lang="ts">
  import { onMount } from 'svelte';
  import type { CertificateData, ExtToWebviewMsg, WebviewToExtMsg } from './types';
  import CertificateView from './lib/CertificateView.svelte';

  // VS Code injects acquireVsCodeApi() into the webview context
  declare function acquireVsCodeApi(): {
    postMessage(msg: WebviewToExtMsg): void;
    getState(): unknown;
    setState(state: unknown): void;
  };

  const vscode = acquireVsCodeApi();

  type AppState = 'idle' | 'loading' | 'ready' | 'error';

  let state: AppState = 'idle';
  let chain: CertificateData[] = [];
  let activeIndex = 0;
  let errorMessage = '';

  $: activeCert = chain[activeIndex] ?? null;

  onMount(() => {
    window.addEventListener('message', (event: MessageEvent<ExtToWebviewMsg>) => {
      const msg = event.data;
      switch (msg.type) {
        case 'loading':
          state = 'loading';
          chain = [];
          errorMessage = '';
          break;
        case 'certificate':
          chain = msg.chain;
          activeIndex = msg.activeIndex;
          state = 'ready';
          break;
        case 'error':
          errorMessage = msg.message;
          state = 'error';
          break;
      }
    });

    vscode.postMessage({ type: 'ready' });
  });

  function handleCopyRequest(event: CustomEvent<string>): void {
    vscode.postMessage({ type: 'copyToClipboard', value: event.detail });
  }

  function selectCert(index: number): void {
    activeIndex = index;
    vscode.postMessage({ type: 'selectCert', index });
  }
</script>

<main>
  {#if state === 'idle'}
    <div class="empty-state">
      <span class="state-icon">🔐</span>
      <h2>X.509 Certificate Viewer</h2>
      <p>
        Select PEM text in the editor and run
        <strong>X.509 Viewer: Show Certificate from Selection</strong>,
        or use <strong>Open Certificate File</strong> to load a PEM / DER file.
      </p>
    </div>

  {:else if state === 'loading'}
    <div class="empty-state">
      <div class="spinner"></div>
      <p>Parsing certificate…</p>
    </div>

  {:else if state === 'error'}
    <div class="error-state">
      <div class="state-icon">⚠️</div>
      <h2>Could not parse certificate</h2>
      <p class="error-message">{errorMessage}</p>
    </div>

  {:else if state === 'ready' && activeCert}
    {#if chain.length > 1}
      <nav class="chain-nav" aria-label="Certificate chain">
        {#each chain as cert, i}
          <button
            class="chain-tab"
            class:active={i === activeIndex}
            on:click={() => selectCert(i)}
            title={cert.subject.raw}
          >
            <span class="chain-index">{i + 1}</span>
            <span class="chain-cn">{cert.subject.commonName ?? cert.subject.raw}</span>
            {#if cert.isCA}
              <span class="badge badge-ca">CA</span>
            {:else}
              <span class="badge badge-ee">EE</span>
            {/if}
          </button>
        {/each}
      </nav>
    {/if}
    <CertificateView cert={activeCert} on:copy={handleCopyRequest} />
  {/if}
</main>

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

  :global(::-webkit-scrollbar) { width: 6px; height: 6px; }
  :global(::-webkit-scrollbar-track) { background: transparent; }
  :global(::-webkit-scrollbar-thumb) {
    background: var(--vscode-scrollbarSlider-background, rgba(255,255,255,0.2));
    border-radius: 3px;
  }

  main { min-height: 100vh; }

  /* ─── Idle / Loading / Error states ─── */
  .empty-state,
  .error-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 2rem;
    text-align: center;
    gap: 0.75rem;
  }

  .empty-state h2,
  .error-state h2 {
    margin: 0;
    font-size: 1.2rem;
    font-weight: 600;
    color: var(--vscode-editor-foreground);
  }

  .empty-state p,
  .error-state p {
    max-width: 420px;
    margin: 0;
    color: var(--vscode-descriptionForeground, #888);
    font-size: 0.88rem;
  }

  .state-icon { font-size: 3rem; line-height: 1; }

  .error-message {
    color: var(--vscode-errorForeground, #f38ba8) !important;
    font-family: var(--vscode-editor-font-family, monospace);
    font-size: 0.8rem !important;
    word-break: break-all;
    background: rgba(243,139,168,0.08);
    padding: 0.5rem 0.75rem;
    border-radius: 4px;
    border: 1px solid rgba(243,139,168,0.25);
  }

  /* ─── Spinner ─── */
  .spinner {
    width: 32px; height: 32px;
    border: 3px solid var(--vscode-panel-border, rgba(255,255,255,0.1));
    border-top-color: var(--vscode-button-background, #7c3aed);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* ─── Chain tabs ─── */
  .chain-nav {
    display: flex;
    flex-wrap: wrap;
    padding: 0.4rem 1rem 0;
    background: var(--vscode-sideBar-background, #181825);
    border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.1));
    gap: 2px;
  }

  .chain-tab {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.4rem 0.8rem;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--vscode-tab-inactiveForeground, #888);
    cursor: pointer;
    font-size: 0.8rem;
    font-family: var(--vscode-font-family);
    transition: color 0.12s, border-color 0.12s;
    max-width: 180px;
  }

  .chain-tab:hover {
    color: var(--vscode-editor-foreground);
    background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.05));
  }

  .chain-tab.active {
    color: var(--vscode-editor-foreground);
    border-bottom-color: var(--vscode-button-background, #7c3aed);
  }

  .chain-index {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 16px; height: 16px;
    border-radius: 50%;
    background: var(--vscode-badge-background, rgba(255,255,255,0.1));
    color: var(--vscode-badge-foreground, #cdd6f4);
    font-size: 0.65rem;
    font-weight: 700;
    flex-shrink: 0;
  }

  .chain-cn {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
  }

  .badge {
    display: inline-block;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: 0.03em;
    flex-shrink: 0;
  }

  .badge-ca {
    background: rgba(148,130,209,0.2);
    color: #b4a7d6;
    border: 1px solid rgba(148,130,209,0.4);
  }

  .badge-ee {
    background: rgba(137,220,235,0.12);
    color: #89dceb;
    border: 1px solid rgba(137,220,235,0.3);
  }
</style>
