/// <reference types="svelte" />

declare function acquireVsCodeApi(): {
  postMessage(msg: any): void;
  getState(): unknown;
  setState(state: unknown): void;
};