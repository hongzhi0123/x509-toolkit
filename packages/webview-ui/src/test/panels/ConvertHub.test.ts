import { render, cleanup, fireEvent, waitFor } from '@testing-library/svelte';
import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import ConvertHub from '../../panels/ConvertHub.svelte';

let postedMessages: unknown[] = [];

beforeEach(() => {
  postedMessages = [];
  (globalThis as Record<string, unknown>).__vscodePostedMessages = postedMessages;
});

afterEach(cleanup);

async function renderMounted() {
  const result = render(ConvertHub);
  await new Promise<void>(resolve => setTimeout(resolve, 0));
  return result;
}

describe('ConvertHub.svelte', () => {
  it('switches modes and renders mode-specific sections', async () => {
    const { getByText, queryByText } = await renderMounted();

    expect(getByText('📤 Extract')).toBeInTheDocument();

    await fireEvent.click(getByText('Build P12'));
    expect(getByText('📦 Build P12')).toBeInTheDocument();

    await fireEvent.click(getByText('Convert Format'));
    expect(getByText('↔ Convert')).toBeInTheDocument();
    expect(queryByText('📤 Extract')).not.toBeInTheDocument();
  });

  it('renders error when extract is attempted without selected file', async () => {
    const { getByText, findByText } = await renderMounted();

    await fireEvent.click(getByText('📤 Extract'));

    expect(await findByText('⚠️ Select a P12 file first.')).toBeInTheDocument();
  });

  it('clears status when switching mode after an error', async () => {
    const { getByText, queryByText } = await renderMounted();

    await fireEvent.click(getByText('📤 Extract'));
    await waitFor(() => expect(queryByText('⚠️ Select a P12 file first.')).toBeInTheDocument());

    await fireEvent.click(getByText('Build P12'));

    expect(queryByText('⚠️ Select a P12 file first.')).not.toBeInTheDocument();
  });

  it('handles file-pick cancel by keeping empty slot and allows error rendering', async () => {
    const { getByText, findByText } = await renderMounted();

    window.dispatchEvent(new MessageEvent('message', {
      data: { type: 'convertFileSelected', slotId: 'p12Input', fileName: '' },
    }));

    expect(getByText('No file selected')).toBeInTheDocument();

    await fireEvent.click(getByText('📤 Extract'));
    expect(await findByText('⚠️ Select a P12 file first.')).toBeInTheDocument();
  });

});
