import * as vscode from 'vscode';
import type sinon from 'sinon';

export function mockExtensionUri(): vscode.Uri {
  return vscode.Uri.file(process.cwd());
}

export function mockContext(): vscode.ExtensionContext {
  return {
    subscriptions: [],
    extensionUri: mockExtensionUri(),
  } as unknown as vscode.ExtensionContext;
}

export async function waitForPostedMessage<T extends { type: string }>(
  postMessageSpy: sinon.SinonSpy,
  type: string,
  timeoutMs = 10_000,
): Promise<T> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const match = findPostedMessage<T>(postMessageSpy, type);
    if (match) {
      return match;
    }
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  throw new Error(`Timed out waiting for webview message type: ${type}`);
}

export function findPostedMessage<T extends { type: string }>(
  postMessageSpy: sinon.SinonSpy,
  type: string,
): T | undefined {
  for (const call of postMessageSpy.getCalls()) {
    const candidate = call.args[0] as { type?: unknown };
    if (candidate && candidate.type === type) {
      return call.args[0] as T;
    }
  }
  return undefined;
}
