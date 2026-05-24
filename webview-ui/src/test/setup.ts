import '@testing-library/jest-dom';

// Stub acquireVsCodeApi — not available outside the VS Code webview sandbox
(globalThis as Record<string, unknown>).acquireVsCodeApi = () => ({
  postMessage: () => {},
  getState: () => undefined,
  setState: () => {},
});
