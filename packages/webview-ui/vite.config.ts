/// <reference types="vitest" />
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'path';

export default defineConfig({
  plugins: [svelte({ hot: !process.env.VITEST })],
  resolve: {
    alias: {
      '@x509-toolkit/core': path.resolve(__dirname, '../core/src/index.ts')
    }
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/lib/**/*.svelte', 'src/panels/**/*.svelte'],
    },
  },
  build: {
    outDir: '../extension/dist/webview',
    emptyOutDir: true,
    rollupOptions: {
      input: 'src/main.ts',
      output: {
        format: 'es',
        entryFileNames: 'main.js',
        chunkFileNames: 'chunk-[hash].js',
        assetFileNames: (info) =>
          info.name?.endsWith('.css') ? 'styles.css' : '[name]-[hash][extname]',
      },
    },
  },
  base: './',
});
