import { render, cleanup, fireEvent } from '@testing-library/svelte';
import { beforeEach, afterEach, describe, expect, it } from 'vitest';

let postedMessages: unknown[] = [];

beforeEach(() => {
  postedMessages = [];
  (globalThis as Record<string, unknown>).__vscodePostedMessages = postedMessages;
});

afterEach(cleanup);

async function renderMounted() {
  const { default: CreateCertPanel } = await import('../../panels/CreateCertPanel.svelte');
  const result = render(CreateCertPanel);
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  return result;
}

function setValue(input: HTMLElement, value: string): Promise<void> {
  return fireEvent.input(input, { target: { value } });
}

function lastPosted<T = unknown>(): T {
  return postedMessages[postedMessages.length - 1] as T;
}

describe('CreateCertPanel.svelte', () => {
  it('shows validation error when CN is missing', async () => {
    const { getByTestId, findByText } = await renderMounted();

    await fireEvent.click(getByTestId('create-cert-generate'));

    expect(await findByText('Common Name (CN) is required.')).toBeInTheDocument();
    expect(postedMessages.some(m => (m as { type?: string }).type === 'generate')).toBe(false);
    expect(postedMessages.some(m => (m as { type?: string }).type === 'generateCsr')).toBe(false);
  });

  it('posts generateCsr in CSR mode with key password and csr params', async () => {
    const { getByTestId } = await renderMounted();

    await setValue(getByTestId('create-cert-cn'), 'csr.example.test');
    await setValue(getByTestId('create-cert-key-password'), 'key-pass-123');
    await fireEvent.click(getByTestId('create-cert-generate'));

    const msg = lastPosted<{ type: string; params: { cn: string; signingMode: string; password: string }; keyPassword: string }>();
    expect(msg.type).toBe('generateCsr');
    expect(msg.keyPassword).toBe('key-pass-123');
    expect(msg.params.cn).toBe('csr.example.test');
    expect(msg.params.signingMode).toBe('csr');
    expect(msg.params.password).toBe('');
  });

  it('validates mismatched P12 passwords in certificate mode', async () => {
    const { getByTestId, findByText } = await renderMounted();

    await fireEvent.click(getByTestId('create-cert-signing-self'));
    await setValue(getByTestId('create-cert-cn'), 'cert.example.test');
    await setValue(getByTestId('create-cert-p12-password'), 'pass-a');
    await setValue(getByTestId('create-cert-p12-password-confirm'), 'pass-b');

    await fireEvent.click(getByTestId('create-cert-generate'));

    expect(await findByText('Passwords do not match.')).toBeInTheDocument();
    expect(postedMessages.some(m => (m as { type?: string }).type === 'generate')).toBe(false);
  });

  it('posts generate in self-signed mode when form is valid', async () => {
    const { getByTestId } = await renderMounted();

    await fireEvent.click(getByTestId('create-cert-signing-self'));
    await setValue(getByTestId('create-cert-cn'), 'self.example.test');
    await setValue(getByTestId('create-cert-p12-password'), 'same-pass');
    await setValue(getByTestId('create-cert-p12-password-confirm'), 'same-pass');

    await fireEvent.click(getByTestId('create-cert-generate'));

    const msg = lastPosted<{ type: string; params: { signingMode: string; cn: string; password: string } }>();
    expect(msg.type).toBe('generate');
    expect(msg.params.signingMode).toBe('self-signed');
    expect(msg.params.cn).toBe('self.example.test');
    expect(msg.params.password).toBe('same-pass');
  });

  it('requires CA cert in ca-signed mode and posts picker actions', async () => {
    const { getByTestId, findByText } = await renderMounted();

    await fireEvent.click(getByTestId('create-cert-signing-ca'));
    await setValue(getByTestId('create-cert-cn'), 'ca-signed.example.test');

    await fireEvent.click(getByTestId('create-cert-generate'));
    expect(await findByText('Please select a CA certificate.')).toBeInTheDocument();

    await fireEvent.click(getByTestId('create-cert-pick-ca-cert'));
    await fireEvent.click(getByTestId('create-cert-pick-ca-key'));

    expect(postedMessages).toContainEqual({ type: 'pickCaCert' });
    expect(postedMessages).toContainEqual({ type: 'pickCaKey' });
    expect(postedMessages.some(m => (m as { type?: string }).type === 'generate')).toBe(false);
  });
});
