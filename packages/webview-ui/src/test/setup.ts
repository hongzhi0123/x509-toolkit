import '@testing-library/jest-dom';

// Stable acquireVsCodeApi stub used by all tests.
// Some components call acquireVsCodeApi at module evaluation time, so we keep
// a singleton object whose postMessage writes into a global sink that tests can reset.
const vscodeApi = {
  postMessage: (msg: unknown) => {
    const sink = (globalThis as Record<string, unknown>).__vscodePostedMessages;
    if (Array.isArray(sink)) sink.push(msg);
  },
  getState: () => undefined,
  setState: () => {},
};

(globalThis as Record<string, unknown>).__vscodePostedMessages = [];
(globalThis as Record<string, unknown>).acquireVsCodeApi = () => vscodeApi;
