import type { Frame } from '@playwright/test';
import { expect } from '@playwright/test';

export class PassphraseDialog {
  constructor(private readonly frame: Frame) {}

  static async waitFor(frame: Frame, timeoutMs = 15_000): Promise<PassphraseDialog> {
    const dialog = frame.getByTestId('passphrase-dialog');
    await expect(dialog).toBeVisible({ timeout: timeoutMs });
    return new PassphraseDialog(frame);
  }

  async fillPassphrase(passphrase: string): Promise<void> {
    await this.frame.getByTestId('passphrase-input').click();
    await this.frame.getByTestId('passphrase-input').fill(passphrase);
  }

  async submit(): Promise<void> {
    await this.frame.getByTestId('passphrase-submit').click();
  }

  async cancel(): Promise<void> {
    await this.frame.getByTestId('passphrase-cancel').click();
  }

  async isVisible(): Promise<boolean> {
    try {
      await expect(this.frame.getByTestId('passphrase-dialog')).toBeVisible({ timeout: 2_000 });
      return true;
    } catch {
      return false;
    }
  }

  async waitForHidden(timeoutMs = 10_000): Promise<void> {
    await expect(this.frame.getByTestId('passphrase-dialog')).not.toBeVisible({
      timeout: timeoutMs,
    });
  }
}
