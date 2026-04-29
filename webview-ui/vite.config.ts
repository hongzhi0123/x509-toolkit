import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: '../dist/webview',
    emptyOutDir: true,
    rollupOptions: {
      output: {
        format: 'iife',
        entryFileNames: 'main.js',
        assetFileNames: (info) =>
          info.name?.endsWith('.css') ? 'styles.css' : '[name]-[hash][extname]',
      },
    },
  },
  base: './',
});
