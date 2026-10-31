import { render, cleanup, fireEvent, waitFor } from '@testing-library/svelte';
import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import type { StandaloneKeyData } from '../../types';

let postedMessages: unknown[] = [];

beforeEach(() => {
  postedMessages = [];
  (globalThis as Record<string, unknown>).__vscodePostedMessages = postedMessages;
});

afterEach(cleanup);

async function renderKeyViewerMounted() {
  const { default: KeyViewer } = await import('../../panels/KeyViewer.svelte');
  const result = render(KeyViewer);
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  return result;
}

async function renderKeyGenMounted() {
  const { default: KeyGenPanel } = await import('../../panels/KeyGenPanel.svelte');
  const result = render(KeyGenPanel);
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  return result;
}

function rsaPrivateKeyFixture(): StandaloneKeyData {
  return {
    kind: 'private',
    algorithm: 'RSA',
    keySize: 2048,
    keyId: 'AA:BB:CC:DD',
    modulus: 'AA:BB',
    publicExponent: '01:00:01',
    isEncrypted: false,
    inputFormat: 'pkcs8-pem',
    spkiPem: '-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----',
    pkcs8Pem: '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----',
  };
}

describe('KeyViewer.svelte', () => {
  it('posts exportPrivateKey with selected format and encryption option', async () => {
    const { default: KeyViewer } = await import('../../panels/KeyViewer.svelte');
    const { getByRole, container } = render(KeyViewer, {
      props: { initialKeyData: rsaPrivateKeyFixture() },
    });

    await waitFor(() => expect(getByRole('button', { name: /Save Private Key/ })).toBeInTheDocument());

    const selects = container.querySelectorAll('select.export-select');
    await fireEvent.change(selects[0], { target: { value: 'pkcs1-der' } });

    const encryptCheckbox = container.querySelector('.encrypt-check input') as HTMLInputElement;
    await fireEvent.click(encryptCheckbox);

    await fireEvent.click(getByRole('button', { name: /Save Private Key/ }));

    expect(postedMessages).toContainEqual({
      type: 'exportPrivateKey',
      format: 'pkcs1-der',
      encrypt: true,
      suggestedName: 'rsa-key',
    });
  });

  it('posts exportPublicKey with selected format', async () => {
    const { default: KeyViewer } = await import('../../panels/KeyViewer.svelte');
    const { getByRole } = render(KeyViewer, {
      props: { initialKeyData: rsaPrivateKeyFixture() },
    });

    await waitFor(() => expect(getByRole('button', { name: /Save Public Key/ })).toBeInTheDocument());

    await fireEvent.click(getByRole('button', { name: /Save Public Key/ }));

    expect(postedMessages).toContainEqual({
      type: 'exportPublicKey',
      format: 'spki-pem',
      suggestedName: 'rsa-pubkey',
    });
  });

  it('posts passphraseResponse with value when passphrase dialog is submitted', async () => {
    const { default: KeyViewer } = await import('../../panels/KeyViewer.svelte');
    const { getByTestId } = render(KeyViewer, {
      props: {
        initialPassphraseRequest: { requestId: 'kv-pass-1', fileName: 'encrypted.key' },
      },
    });

    await waitFor(() => expect(getByTestId('passphrase-dialog')).toBeInTheDocument());

    await fireEvent.input(getByTestId('passphrase-input'), { target: { value: 'secret-pass' } });
    await fireEvent.click(getByTestId('passphrase-submit'));

    expect(postedMessages).toContainEqual({
      type: 'passphraseResponse',
      requestId: 'kv-pass-1',
      passphrase: 'secret-pass',
    });
  });

  it('posts passphraseResponse with null when passphrase dialog is cancelled', async () => {
    const { default: KeyViewer } = await import('../../panels/KeyViewer.svelte');
    const { getByTestId } = render(KeyViewer, {
      props: {
        initialPassphraseRequest: { requestId: 'kv-pass-2', fileName: 'encrypted.key' },
      },
    });

    await waitFor(() => expect(getByTestId('passphrase-dialog')).toBeInTheDocument());

    await fireEvent.click(getByTestId('passphrase-cancel'));

    expect(postedMessages).toContainEqual({
      type: 'passphraseResponse',
      requestId: 'kv-pass-2',
      passphrase: null,
    });
  });
});

describe('KeyGenPanel.svelte', () => {
  it('posts keyGenGenerate with selected algorithm', async () => {
    const { container, getByRole } = await renderKeyGenMounted();

    const select = container.querySelector('#algo-select') as HTMLSelectElement;
    await fireEvent.change(select, { target: { value: 'RSA-4096' } });
    await fireEvent.click(getByRole('button', { name: /^Generate Key Pair$/ }));

    expect(postedMessages).toContainEqual({
      type: 'keyGenGenerate',
      algorithm: 'RSA-4096',
    });
  });

  it('posts save/view actions in done state', async () => {
    const { default: KeyGenPanel } = await import('../../panels/KeyGenPanel.svelte');
    const { getByRole } = render(KeyGenPanel, {
      props: { initialGeneratedKey: rsaPrivateKeyFixture() },
    });

    await waitFor(() => expect(getByRole('button', { name: /Save Private Key/ })).toBeInTheDocument());

    await fireEvent.click(getByRole('button', { name: /Save Private Key/ }));
    await fireEvent.click(getByRole('button', { name: /Save Public Key/ }));
    await fireEvent.click(getByRole('button', { name: /Open in Key Viewer/ }));

    expect(postedMessages).toContainEqual({ type: 'keyGenSavePrivateKey' });
    expect(postedMessages).toContainEqual({ type: 'keyGenSavePublicKey' });
    expect(postedMessages).toContainEqual({ type: 'keyGenViewKey' });
  });

  it('posts inputDialogResponse with null when dialog is cancelled', async () => {
    const { default: KeyGenPanel } = await import('../../panels/KeyGenPanel.svelte');
    const { getByRole } = render(KeyGenPanel, {
      props: {
        initialInputDialog: {
          requestId: 'kg-input-1',
          title: 'Save key',
          fields: [{ id: 'name', label: 'Name', required: true }],
        },
      },
    });

    await waitFor(() => expect(getByRole('dialog')).toBeInTheDocument());

    await fireEvent.click(getByRole('button', { name: 'Cancel' }));

    expect(postedMessages).toContainEqual({
      type: 'inputDialogResponse',
      requestId: 'kg-input-1',
      values: null,
    });
  });
});
