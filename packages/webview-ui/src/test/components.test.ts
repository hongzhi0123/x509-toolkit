import { render, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, vi } from 'vitest';
import ValidityIndicator from '../lib/ValidityIndicator.svelte';
import FieldRow from '../lib/FieldRow.svelte';
import HexValue from '../lib/HexValue.svelte';
import SectionCard from '../lib/SectionCard.svelte';
import Fingerprints from '../lib/Fingerprints.svelte';
import type { Validity, Fingerprints as FP } from '../types';

// ---------------------------------------------------------------------------
// ValidityIndicator
// ---------------------------------------------------------------------------
describe('ValidityIndicator', () => {
  function validity(overrides: Partial<Validity>): Validity {
    return {
      notBefore: '2024-01-01T00:00:00Z',
      notAfter: '2025-01-01T00:00:00Z',
      isExpired: false,
      daysRemaining: 365,
      ...overrides,
    };
  }

  it('shows ✓ and "valid" class when certificate is healthy', () => {
    const { container, getByText } = render(ValidityIndicator, {
      props: { validity: validity({ daysRemaining: 365 }) },
    });
    expect(getByText('✓')).toBeInTheDocument();
    expect(container.querySelector('.vi-valid')).toBeInTheDocument();
  });

  it('shows ⚠ and "warning" class when 15 days remain', () => {
    const { container, getByText } = render(ValidityIndicator, {
      props: { validity: validity({ daysRemaining: 15 }) },
    });
    expect(getByText('⚠')).toBeInTheDocument();
    expect(container.querySelector('.vi-warning')).toBeInTheDocument();
  });

  it('shows ⚠ and "critical" class when 3 days remain', () => {
    const { container, getByText } = render(ValidityIndicator, {
      props: { validity: validity({ daysRemaining: 3 }) },
    });
    expect(getByText('⚠')).toBeInTheDocument();
    expect(container.querySelector('.vi-critical')).toBeInTheDocument();
  });

  it('shows ✗ and "expired" class when certificate is expired', () => {
    const { container, getByText } = render(ValidityIndicator, {
      props: { validity: validity({ isExpired: true, daysRemaining: -10 }) },
    });
    expect(getByText('✗')).toBeInTheDocument();
    expect(container.querySelector('.vi-expired')).toBeInTheDocument();
  });

  it('label says "Expires today!" when daysRemaining is 0', () => {
    const { getByText } = render(ValidityIndicator, {
      props: { validity: validity({ daysRemaining: 0 }) },
    });
    expect(getByText('Expires today!')).toBeInTheDocument();
  });

  it('label includes day count when expired', () => {
    const { getByText } = render(ValidityIndicator, {
      props: { validity: validity({ isExpired: true, daysRemaining: -5 }) },
    });
    expect(getByText(/Expired 5 day\(s\) ago/)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// FieldRow
// ---------------------------------------------------------------------------
describe('FieldRow', () => {
  it('renders label and value', () => {
    const { getByText } = render(FieldRow, {
      props: { label: 'Common Name', value: 'example.com' },
    });
    expect(getByText('Common Name')).toBeInTheDocument();
    expect(getByText('example.com')).toBeInTheDocument();
  });

  it('does not render copy button when copyable is false', () => {
    const { queryByTitle } = render(FieldRow, {
      props: { label: 'L', value: 'v', copyable: false },
    });
    expect(queryByTitle('Copy')).not.toBeInTheDocument();
  });

  it('renders copy button when copyable is true', () => {
    const { getByTitle } = render(FieldRow, {
      props: { label: 'L', value: 'v', copyable: true },
    });
    expect(getByTitle('Copy')).toBeInTheDocument();
  });

  it('dispatches copy event when copy button clicked', async () => {
    const { getByTitle, component } = render(FieldRow, {
      props: { label: 'L', value: 'v', copyable: true },
    });
    const handler = vi.fn();
    component.$on('copy', handler);
    await fireEvent.click(getByTitle('Copy'));
    expect(handler).toHaveBeenCalledOnce();
  });

  it('applies mono class when mono prop is true', () => {
    const { container } = render(FieldRow, {
      props: { label: 'L', value: 'v', mono: true },
    });
    expect(container.querySelector('.fv.mono')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// HexValue
// ---------------------------------------------------------------------------
describe('HexValue', () => {
  const SHORT = 'AA:BB:CC:DD';
  const LONG = Array.from({ length: 30 }, (_, i) => i.toString(16).padStart(2, '0').toUpperCase()).join(':');

  it('displays byte count', () => {
    const { getByText } = render(HexValue, { props: { value: SHORT } });
    expect(getByText('4 bytes')).toBeInTheDocument();
  });

  it('shows copy button', () => {
    const { getByTitle } = render(HexValue, { props: { value: SHORT } });
    expect(getByTitle('Copy hex')).toBeInTheDocument();
  });

  it('dispatches copy event when copy button clicked', async () => {
    const { getByTitle, component } = render(HexValue, { props: { value: SHORT } });
    const handler = vi.fn();
    component.$on('copy', handler);
    await fireEvent.click(getByTitle('Copy hex'));
    expect(handler).toHaveBeenCalledOnce();
  });

  it('does not show expand button for short values', () => {
    const { queryByText } = render(HexValue, { props: { value: SHORT } });
    expect(queryByText(/Show all/)).not.toBeInTheDocument();
  });

  it('shows expand button for long values', () => {
    const { getByText } = render(HexValue, { props: { value: LONG } });
    expect(getByText(`Show all 30 bytes`)).toBeInTheDocument();
  });

  it('expands to show all bytes when expand button clicked', async () => {
    const { getByText } = render(HexValue, { props: { value: LONG } });
    await fireEvent.click(getByText(`Show all 30 bytes`));
    expect(getByText('Show less')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// SectionCard
// ---------------------------------------------------------------------------
describe('SectionCard', () => {
  it('renders the title', () => {
    const { getByText } = render(SectionCard, { props: { title: 'Subject' } });
    expect(getByText('Subject')).toBeInTheDocument();
  });

  it('is expanded by default', () => {
    const { getByRole } = render(SectionCard, { props: { title: 'T' } });
    expect(getByRole('button')).toHaveAttribute('aria-expanded', 'true');
  });

  it('starts collapsed when collapsed prop is true', () => {
    const { getByRole } = render(SectionCard, {
      props: { title: 'T', collapsed: true },
    });
    expect(getByRole('button')).toHaveAttribute('aria-expanded', 'false');
  });

  it('toggles open/closed when header is clicked', async () => {
    const { getByRole } = render(SectionCard, { props: { title: 'T' } });
    const btn = getByRole('button');
    expect(btn).toHaveAttribute('aria-expanded', 'true');
    await fireEvent.click(btn);
    expect(btn).toHaveAttribute('aria-expanded', 'false');
    await fireEvent.click(btn);
    expect(btn).toHaveAttribute('aria-expanded', 'true');
  });

  it('renders icon when icon prop is supplied', () => {
    const { getByText } = render(SectionCard, { props: { title: 'T', icon: '🔑' } });
    expect(getByText('🔑')).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------
describe('Fingerprints', () => {
  const fps: FP = {
    sha1: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
    sha256: '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
  };

  it('renders SHA-1 and SHA-256 labels', () => {
    const { getByText } = render(Fingerprints, { props: { fingerprints: fps } });
    expect(getByText('SHA-1')).toBeInTheDocument();
    expect(getByText('SHA-256')).toBeInTheDocument();
  });

  it('renders both fingerprint values', () => {
    const { getByText } = render(Fingerprints, { props: { fingerprints: fps } });
    expect(getByText(fps.sha1)).toBeInTheDocument();
    expect(getByText(fps.sha256)).toBeInTheDocument();
  });

  it('shows SHA-1 weak warning', () => {
    const { getByText } = render(Fingerprints, { props: { fingerprints: fps } });
    expect(getByText('⚠ weak')).toBeInTheDocument();
  });

  it('dispatches copy event with sha1 value', async () => {
    const { getAllByTitle, component } = render(Fingerprints, { props: { fingerprints: fps } });
    const handler = vi.fn();
    component.$on('copy', handler);
    await fireEvent.click(getAllByTitle('Copy SHA-1')[0]);
    expect(handler).toHaveBeenCalledOnce();
    expect(handler.mock.calls[0][0].detail).toBe(fps.sha1);
  });

  it('dispatches copy event with sha256 value', async () => {
    const { getAllByTitle, component } = render(Fingerprints, { props: { fingerprints: fps } });
    const handler = vi.fn();
    component.$on('copy', handler);
    await fireEvent.click(getAllByTitle('Copy SHA-256')[0]);
    expect(handler).toHaveBeenCalledOnce();
    expect(handler.mock.calls[0][0].detail).toBe(fps.sha256);
  });
});
