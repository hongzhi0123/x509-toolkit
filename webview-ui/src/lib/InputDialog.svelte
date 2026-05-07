<script lang="ts">
  import { createEventDispatcher, onMount, tick } from 'svelte';

  // ── Field descriptor ──────────────────────────────────────────────────────
  export interface DialogField {
    /** Unique key used in the result map */
    id: string;
    /** Label shown above the input */
    label: string;
    /** Input type.  'select' renders a <select>; 'number'/'date' use native inputs */
    type?: 'text' | 'password' | 'number' | 'date' | 'select';
    /** Initial value */
    value?: string;
    /** Placeholder text (text/password/number) */
    placeholder?: string;
    /** Options for type='select' – { value, label } pairs */
    options?: Array<{ value: string; label: string }>;
    /** Mark field as required; empty value blocks submission */
    required?: boolean;
    /** Small hint rendered below the field */
    hint?: string;
    /** Minimum value / date string */
    min?: string;
    /** Maximum value / date string */
    max?: string;
    /** Step for type='number' */
    step?: number;
  }

  // ── Component props ───────────────────────────────────────────────────────
  /** Dialog title */
  export let title: string = 'Enter Information';
  /** Optional icon character/emoji shown next to the title */
  export let icon: string = '';
  /** Optional subtitle / description */
  export let description: string = '';
  /** Fields to render */
  export let fields: DialogField[] = [];
  /** Label for the confirm button */
  export let confirmLabel: string = 'OK';
  /** Label for the cancel button */
  export let cancelLabel: string = 'Cancel';

  // ── Internal state ────────────────────────────────────────────────────────
  const dispatch = createEventDispatcher<{
    /** Fired on confirmation; values keyed by field id */
    confirm: Record<string, string>;
    cancel: void;
  }>();

  // Clone initial values so we don't mutate the prop directly
  let values: Record<string, string> = {};
  fields.forEach(f => { values[f.id] = f.value ?? ''; });

  // Track which fields have been touched to show validation errors lazily
  let touched: Record<string, boolean> = {};

  $: fieldErrors = fields.reduce((acc, f) => {
    if (f.required && !values[f.id]?.trim()) {
      acc[f.id] = `${f.label} is required.`;
    }
    return acc;
  }, {} as Record<string, string>);

  $: canSubmit = Object.keys(fieldErrors).length === 0;

  let dialogEl: HTMLElement;

  onMount(() => {
    tick().then(() => {
      const el = dialogEl?.querySelector<HTMLElement>('input, select');
      el?.focus();
    });
  });

  function submit() {
    // Touch all fields so errors become visible
    fields.forEach(f => { touched[f.id] = true; });
    touched = { ...touched };
    if (!canSubmit) return;
    dispatch('confirm', { ...values });
  }

  function cancel() {
    dispatch('cancel');
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      // Don't submit on Enter inside a textarea or select (multi-select)
      const tag = (e.target as HTMLElement).tagName;
      if (tag === 'TEXTAREA') return;
      e.preventDefault();
      submit();
    }
    if (e.key === 'Escape') { e.preventDefault(); cancel(); }
  }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events a11y-no-static-element-interactions -->
<div class="backdrop" on:click|self={cancel}>
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div
    class="dialog"
    role="dialog"
    aria-modal="true"
    aria-labelledby="input-dlg-title"
    on:keydown={handleKeydown}
    bind:this={dialogEl}
  >
    <!-- Header -->
    <div class="dialog-header">
      {#if icon}<span class="dialog-icon" aria-hidden="true">{icon}</span>{/if}
      <h2 id="input-dlg-title">{title}</h2>
    </div>

    <!-- Optional description -->
    {#if description}
      <p class="dialog-desc">{description}</p>
    {/if}

    <!-- Fields -->
    <div class="fields">
      {#each fields as field, idx (field.id)}
        {@const hasError = touched[field.id] && !!fieldErrors[field.id]}
        <div class="field-group">
          <label class="field-label" for="dlg-field-{field.id}">
            {field.label}{field.required ? ' *' : ''}
          </label>

          {#if field.type === 'select'}
            <select
              id="dlg-field-{field.id}"
              bind:value={values[field.id]}
              class="field-input"
              class:field-input-error={hasError}
              on:blur={() => { touched[field.id] = true; touched = { ...touched }; }}
            >
              {#if !field.required}
                <option value="">— select —</option>
              {/if}
              {#each (field.options ?? []) as opt}
                <option value={opt.value}>{opt.label}</option>
              {/each}
            </select>

          {:else if field.type === 'password'}
            <input
              id="dlg-field-{field.id}"
              bind:value={values[field.id]}
              type="password"
              class="field-input"
              class:field-input-error={hasError}
              placeholder={field.placeholder ?? ''}
              autocomplete="off"
              spellcheck="false"
              on:blur={() => { touched[field.id] = true; touched = { ...touched }; }}
            />

          {:else if field.type === 'number'}
            <input
              id="dlg-field-{field.id}"
              bind:value={values[field.id]}
              type="number"
              class="field-input"
              class:field-input-error={hasError}
              placeholder={field.placeholder ?? ''}
              min={field.min}
              max={field.max}
              step={field.step}
              spellcheck="false"
              on:blur={() => { touched[field.id] = true; touched = { ...touched }; }}
            />

          {:else if field.type === 'date'}
            <input
              id="dlg-field-{field.id}"
              bind:value={values[field.id]}
              type="date"
              class="field-input"
              class:field-input-error={hasError}
              min={field.min}
              max={field.max}
              on:blur={() => { touched[field.id] = true; touched = { ...touched }; }}
            />

          {:else}
            <!-- text (default) -->
            <input
              id="dlg-field-{field.id}"
              bind:value={values[field.id]}
              type="text"
              class="field-input"
              class:field-input-error={hasError}
              placeholder={field.placeholder ?? ''}
              spellcheck="false"
              on:blur={() => { touched[field.id] = true; touched = { ...touched }; }}
            />
          {/if}

          {#if hasError}
            <span class="field-error" role="alert">{fieldErrors[field.id]}</span>
          {:else if field.hint}
            <span class="field-hint">{field.hint}</span>
          {/if}
        </div>
      {/each}
    </div>

    <!-- Footer -->
    <div class="dialog-footer">
      <button class="btn btn-cancel" type="button" on:click={cancel}>{cancelLabel}</button>
      <button class="btn btn-ok" type="button" on:click={submit} disabled={!canSubmit && Object.values(touched).some(Boolean)}>
        {confirmLabel}
      </button>
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
    border: 1px solid var(--vscode-focusBorder, rgba(255, 255, 255, 0.2));
    border-radius: 8px;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.55);
    width: 100%;
    max-width: 420px;
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

  .dialog-icon {
    font-size: 1.3rem;
    line-height: 1;
    flex-shrink: 0;
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

  /* ── Fields ──────────────────────────────────────────────────────────── */
  .fields {
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
  }

  .field-group {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }

  .field-label {
    font-size: 0.78rem;
    color: var(--vscode-descriptionForeground, #aaa);
    font-weight: 500;
  }

  .field-input {
    width: 100%;
    padding: 0.48rem 0.65rem;
    background: var(--vscode-input-background, rgba(0, 0, 0, 0.25));
    color: var(--vscode-input-foreground, var(--vscode-editor-foreground));
    border: 1px solid var(--vscode-input-border, rgba(255, 255, 255, 0.15));
    border-radius: 4px;
    font-size: 0.88rem;
    font-family: var(--vscode-font-family);
    outline: none;
    box-sizing: border-box;
    transition: border-color 0.15s;
    appearance: none;
    -webkit-appearance: none;
  }

  select.field-input {
    /* Re-add a minimal chevron for selects */
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23888'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 0.65rem center;
    padding-right: 2rem;
    cursor: pointer;
  }

  .field-input:focus {
    border-color: var(--vscode-focusBorder, #569cd6);
  }

  .field-input-error {
    border-color: var(--vscode-inputValidation-errorBorder, #be1100) !important;
  }

  .field-error {
    font-size: 0.75rem;
    color: var(--vscode-inputValidation-errorForeground, #f48771);
  }

  .field-hint {
    font-size: 0.75rem;
    color: var(--vscode-descriptionForeground, #888);
  }

  /* ── Footer ──────────────────────────────────────────────────────────── */
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
    background: var(--vscode-button-secondaryBackground, rgba(255, 255, 255, 0.07));
    color: var(--vscode-button-secondaryForeground, var(--vscode-editor-foreground));
    border-color: var(--vscode-panel-border, rgba(255, 255, 255, 0.12));
  }

  .btn-cancel:hover {
    background: var(--vscode-button-secondaryHoverBackground, rgba(255, 255, 255, 0.12));
  }

  .btn-ok {
    background: var(--vscode-button-background, #0e639c);
    color: var(--vscode-button-foreground, #fff);
    font-weight: 600;
  }

  .btn-ok:hover:not(:disabled) {
    background: var(--vscode-button-hoverBackground, #1177bb);
  }

  .btn-ok:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
</style>
