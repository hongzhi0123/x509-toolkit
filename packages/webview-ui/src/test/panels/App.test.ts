import { render, cleanup, waitFor, fireEvent } from '@testing-library/svelte';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import App from '../../panels/App.svelte';
import type { CertificateData, CsrData } from '../../types';

// ──────────────────────────────────────────────────────────────────────────────
// Fixtures
// ──────────────────────────────────────────────────────────────────────────────

function sampleCert(overrides?: Partial<CertificateData>): CertificateData {
  return {
    version: 3,
    serialNumber: '01',
    subject: { raw: 'CN=test.example.com', commonName: 'test.example.com' },
    issuer: { raw: 'CN=test.example.com', commonName: 'test.example.com' },
    validity: {
      notBefore: '2024-01-01T00:00:00Z',
      notAfter: '2030-01-01T00:00:00Z',
      isExpired: false,
      daysRemaining: 2000,
    },
    publicKey: {
      algorithm: 'RSA',
      keySize: 2048,
      spki: 'AA:BB:CC:DD',
      spkiPem: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG\n-----END PUBLIC KEY-----',
    },
    signature: { algorithm: 'SHA256-RSA', value: 'AA:BB:CC' },
    extensions: [],
    fingerprints: {
      sha1: 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD',
      sha256: '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
    },
    raw: '-----BEGIN CERTIFICATE-----\nMIIF...\n-----END CERTIFICATE-----',
    isCA: false,
    isSelfSigned: true,
    ...overrides,
  };
}

function sampleCsr(): CsrData {
  return {
    subject: { raw: 'CN=csr.example.com', commonName: 'csr.example.com' },
    publicKey: {
      algorithm: 'RSA',
      keySize: 2048,
      spki: 'AA:BB:CC:DD',
      spkiPem: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG\n-----END PUBLIC KEY-----',
    },
    signatureAlgorithm: 'SHA256-RSA',
    extensions: [],
    raw: '-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----',
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-test acquireVsCodeApi mock that captures posted messages
// ──────────────────────────────────────────────────────────────────────────────

let postedMessages: unknown[] = [];

beforeEach(() => {
  postedMessages = [];
  (globalThis as Record<string, unknown>).acquireVsCodeApi = () => ({
    postMessage: (msg: unknown) => { postedMessages.push(msg); },
    getState: () => undefined,
    setState: () => {},
  });
});

afterEach(cleanup);

// ──────────────────────────────────────────────────────────────────────────────
// Helper: dispatch an extension-to-webview message
// ──────────────────────────────────────────────────────────────────────────────

function sendMessage(data: Record<string, unknown>): void {
  window.dispatchEvent(new MessageEvent('message', { data }));
}

// ──────────────────────────────────────────────────────────────────────────────
// Helper: render App and let Svelte's scheduler flush onMount.
// onMount is where the window message listener is registered.  We must yield to
// the microtask queue (via tick()) so the listener is in place before any test
// message is dispatched.
// ──────────────────────────────────────────────────────────────────────────────

async function renderMounted(): Promise<ReturnType<typeof render<typeof App>>> {
  const result = render(App);
  // A macrotask boundary (setTimeout 0) ensures all pending microtasks —
  // including Svelte 4's onMount scheduler — have been processed before
  // we return. After this, the window message listener is registered.
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  return result;
}

// ──────────────────────────────────────────────────────────────────────────────
// Idle state
// ──────────────────────────────────────────────────────────────────────────────

describe('App.svelte — idle state', () => {
  it('shows the idle state indicator on first render', () => {
    const { getByTestId } = render(App);
    expect(getByTestId('viewer-state-idle')).toBeInTheDocument();
  });

  it('posts { type: "ready" } to the extension on mount', async () => {
    await renderMounted();
    await waitFor(() => {
      expect(postedMessages).toContainEqual({ type: 'ready' });
    });
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Loading state
// ──────────────────────────────────────────────────────────────────────────────

describe('App.svelte — loading state', () => {
  it('transitions to loading state on "loading" message', async () => {
    const { getByTestId } = await renderMounted();
    sendMessage({ type: 'loading' });
    await waitFor(() => expect(getByTestId('viewer-state-loading')).toBeInTheDocument());
  });

  it('shows default spinner text when no status is provided', async () => {
    const { getByText } = await renderMounted();
    sendMessage({ type: 'loading' });
    await waitFor(() => expect(getByText('Parsing certificate…')).toBeInTheDocument());
  });

  it('shows custom status text when provided in the loading message', async () => {
    const { getByText } = await renderMounted();
    sendMessage({ type: 'loading', status: 'Connecting to TLS server…' });
    await waitFor(() => expect(getByText('Connecting to TLS server…')).toBeInTheDocument());
  });

  it('updates the step text when a tlsProgress message arrives', async () => {
    const { getByText } = await renderMounted();
    sendMessage({ type: 'loading' });
    sendMessage({ type: 'tlsProgress', step: 'TLS handshake complete' });
    await waitFor(() => expect(getByText('TLS handshake complete')).toBeInTheDocument());
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Ready state
// ──────────────────────────────────────────────────────────────────────────────

describe('App.svelte — ready state', () => {
  it('transitions to ready state on "certificate" message', async () => {
    const { getByTestId } = await renderMounted();
    sendMessage({ type: 'certificate', chain: [sampleCert()], activeIndex: 0 });
    await waitFor(() => expect(getByTestId('viewer-state-ready')).toBeInTheDocument());
  });

  it('hides the idle state indicator once the certificate arrives', async () => {
    const { queryByTestId } = await renderMounted();
    sendMessage({ type: 'certificate', chain: [sampleCert()], activeIndex: 0 });
    await waitFor(() => expect(queryByTestId('viewer-state-idle')).not.toBeInTheDocument());
  });

  it('transitions back to loading when a subsequent "loading" message arrives', async () => {
    const { getByTestId } = await renderMounted();
    sendMessage({ type: 'certificate', chain: [sampleCert()], activeIndex: 0 });
    await waitFor(() => expect(getByTestId('viewer-state-ready')).toBeInTheDocument());
    sendMessage({ type: 'loading' });
    await waitFor(() => expect(getByTestId('viewer-state-loading')).toBeInTheDocument());
  });

  it('renders chain navigation when more than one cert is provided', async () => {
    const { getByTestId } = await renderMounted();
    sendMessage({
      type: 'certificate',
      chain: [
        sampleCert({ subject: { raw: 'CN=leaf', commonName: 'leaf' } }),
        sampleCert({ subject: { raw: 'CN=root', commonName: 'root' }, isCA: true }),
      ],
      activeIndex: 0,
    });
    await waitFor(() => expect(getByTestId('viewer-chain-nav')).toBeInTheDocument());
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Error state
// ──────────────────────────────────────────────────────────────────────────────

describe('App.svelte — error state', () => {
  it('transitions to error state on "error" message', async () => {
    const { getByTestId } = await renderMounted();
    sendMessage({ type: 'error', message: 'Could not parse certificate' });
    await waitFor(() => expect(getByTestId('viewer-state-error')).toBeInTheDocument());
  });

  it('displays the error message text', async () => {
    const { getByText } = await renderMounted();
    sendMessage({ type: 'error', message: 'Incorrect password or corrupted file' });
    await waitFor(() => expect(getByText('Incorrect password or corrupted file')).toBeInTheDocument());
  });

  it('hides the idle indicator once an error message arrives', async () => {
    const { queryByTestId } = await renderMounted();
    sendMessage({ type: 'error', message: 'Parse failed' });
    await waitFor(() => expect(queryByTestId('viewer-state-idle')).not.toBeInTheDocument());
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// CSR state
// ──────────────────────────────────────────────────────────────────────────────

describe('App.svelte — CSR state', () => {
  it('leaves idle state when a "csr" message is received', async () => {
    const { queryByTestId } = await renderMounted();
    sendMessage({ type: 'csr', data: sampleCsr() });
    await waitFor(() => expect(queryByTestId('viewer-state-idle')).not.toBeInTheDocument());
  });

  it('does not show loading or error state for a CSR message', async () => {
    const { queryByTestId } = await renderMounted();
    sendMessage({ type: 'csr', data: sampleCsr() });
    await waitFor(() => expect(queryByTestId('viewer-state-idle')).not.toBeInTheDocument());
    expect(queryByTestId('viewer-state-loading')).not.toBeInTheDocument();
    expect(queryByTestId('viewer-state-error')).not.toBeInTheDocument();
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Passphrase dialog round-trip
// ──────────────────────────────────────────────────────────────────────────────

describe('App.svelte — passphrase dialog', () => {
  it('shows the passphrase dialog on "requestPassphrase" message', async () => {
    const { getByTestId } = await renderMounted();
    sendMessage({ type: 'requestPassphrase', requestId: 'r1', fileName: 'test.p12' });
    await waitFor(() => expect(getByTestId('passphrase-dialog')).toBeInTheDocument());
  });

  it('hides the passphrase dialog after the submit button is clicked', async () => {
    const { getByTestId, queryByTestId } = await renderMounted();
    sendMessage({ type: 'requestPassphrase', requestId: 'r2', fileName: 'test.p12' });
    await waitFor(() => expect(getByTestId('passphrase-dialog')).toBeInTheDocument());
    await fireEvent.click(getByTestId('passphrase-submit'));
    await waitFor(() => expect(queryByTestId('passphrase-dialog')).not.toBeInTheDocument());
  });

  it('posts passphraseResponse with the typed passphrase on submit', async () => {
    const { getByTestId } = await renderMounted();
    sendMessage({ type: 'requestPassphrase', requestId: 'r3', fileName: 'test.p12' });
    await waitFor(() => expect(getByTestId('passphrase-dialog')).toBeInTheDocument());

    const input = getByTestId('passphrase-input');
    await fireEvent.input(input, { target: { value: 'mysecretpass' } });
    await fireEvent.click(getByTestId('passphrase-submit'));

    await waitFor(() => {
      expect(postedMessages).toContainEqual({
        type: 'passphraseResponse',
        requestId: 'r3',
        passphrase: 'mysecretpass',
      });
    });
  });

  it('posts passphraseResponse with null when the dialog is cancelled', async () => {
    const { getByTestId, queryByTestId } = await renderMounted();
    sendMessage({ type: 'requestPassphrase', requestId: 'r4', fileName: 'test.p12' });
    await waitFor(() => expect(getByTestId('passphrase-dialog')).toBeInTheDocument());
    await fireEvent.click(getByTestId('passphrase-cancel'));
    await waitFor(() => {
      expect(postedMessages).toContainEqual({
        type: 'passphraseResponse',
        requestId: 'r4',
        passphrase: null,
      });
    });
    expect(queryByTestId('passphrase-dialog')).not.toBeInTheDocument();
  });

  it('does not show the passphrase dialog on initial render', () => {
    const { queryByTestId } = render(App);
    expect(queryByTestId('passphrase-dialog')).not.toBeInTheDocument();
  });
});
