import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

// Dev-server proxy targets (override for a second laptop or an alternate local API instance).
const apiTarget = process.env['VITE_PROXY_API_TARGET'] || 'http://localhost:4000';
const witnessTarget = process.env['VITE_PROXY_WITNESS_TARGET'] || 'http://localhost:4001';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: Number(process.env['VITE_PORT']) || 5173,
    proxy: {
      '/api': {
        target: apiTarget,
        changeOrigin: true,
      },
      '/witness': {
        target: witnessTarget,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
