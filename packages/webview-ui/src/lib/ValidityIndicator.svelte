<script lang="ts">
  import type { Validity } from '../types';

  export let validity: Validity;

  $: status = validity.isExpired ? 'expired'
    : validity.daysRemaining <= 7 ? 'critical'
    : validity.daysRemaining <= 30 ? 'warning'
    : 'valid';

  $: icon = validity.isExpired ? '✗'
    : validity.daysRemaining <= 30 ? '⚠'
    : '✓';

  $: label = validity.isExpired
    ? `Expired ${Math.abs(validity.daysRemaining)} day(s) ago`
    : validity.daysRemaining === 0
      ? 'Expires today!'
      : validity.daysRemaining <= 7
        ? `Expires in ${validity.daysRemaining} day(s) — critical!`
        : validity.daysRemaining <= 30
          ? `Expires in ${validity.daysRemaining} days`
          : `Valid (${validity.daysRemaining} days remaining)`;
</script>

<div class="vi vi-{status}" title={label}>
  <span class="vi-icon">{icon}</span>
  <span class="vi-label">{label}</span>
</div>

<style>
  .vi {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.3rem 0.65rem;
    border-radius: 5px;
    font-size: 0.78rem;
    font-weight: 600;
    white-space: nowrap;
    flex-shrink: 0;
  }

  .vi-valid   { background: rgba(166,227,161,0.13); color: #a6e3a1; border: 1px solid rgba(166,227,161,0.28); }
  .vi-warning { background: rgba(249,226,175,0.13); color: #f9e2af; border: 1px solid rgba(249,226,175,0.32); }
  .vi-critical{ background: rgba(250,179,135,0.13); color: #fab387; border: 1px solid rgba(250,179,135,0.32); }
  .vi-expired { background: rgba(243,139,168,0.13); color: #f38ba8; border: 1px solid rgba(243,139,168,0.28); }

  .vi-icon { font-size: 0.88rem; line-height: 1; font-style: normal; }
</style>
