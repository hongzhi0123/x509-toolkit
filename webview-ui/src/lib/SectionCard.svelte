<script lang="ts">
  export let title: string;
  export let icon: string = '';
  export let collapsed: boolean = false;

  let open = !collapsed;
  function toggle(): void { open = !open; }
</script>

<div class="section-card">
  <button class="sec-hdr" on:click={toggle} aria-expanded={open}>
    <span class="sec-left">
      {#if icon}<span class="sec-icon" aria-hidden="true">{icon}</span>{/if}
      <span class="sec-title">{title}</span>
    </span>
    <span class="chevron" style="transform: rotate({open ? '270deg' : '90deg'})">›</span>
  </button>
  {#if open}
    <div class="sec-body">
      <slot />
    </div>
  {/if}
</div>

<style>
  .section-card {
    border: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.08));
    border-radius: 6px;
    overflow: hidden;
    background: var(--vscode-editor-background, #1e1e2e);
  }

  .sec-hdr {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 0.6rem 0.8rem;
    background: var(--vscode-sideBarSectionHeader-background, rgba(255,255,255,0.04));
    border: none;
    cursor: pointer;
    color: var(--vscode-editor-foreground);
    font-family: var(--vscode-font-family);
    font-size: 0.8rem;
    font-weight: 600;
    text-align: left;
    transition: background 0.12s;
    gap: 0.5rem;
  }

  .sec-hdr:hover {
    background: var(--vscode-list-hoverBackground, rgba(255,255,255,0.07));
  }

  .sec-left {
    display: flex;
    align-items: center;
    gap: 0.45rem;
  }

  .sec-icon { font-size: 0.95rem; line-height: 1; }
  .sec-title { letter-spacing: 0.01em; }

  .chevron {
    font-size: 0.95rem;
    color: var(--vscode-descriptionForeground, #888);
    display: inline-block;
    line-height: 1;
    transition: transform 0.18s ease;
  }

  .sec-body {
    border-top: 1px solid var(--vscode-panel-border, rgba(255,255,255,0.06));
  }
</style>
