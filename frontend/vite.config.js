import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// Served from https://sukhi-superman.github.io/PQC-ready-check/
export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), 'VITE_'), ...process.env };
  let apiOrigin = '';
  if (env.VITE_API_URL) {
    apiOrigin = new URL(env.VITE_API_URL).origin; // throws on a malformed URL at build time
  }
  return {
    base: '/PQC-ready-check/',
    plugins: [
      react(),
      tailwindcss(),
      {
        // The Content-Security-Policy only allows fetches to this site and the configured API origin.
        name: 'csp-api-origin',
        transformIndexHtml: (html) => html.replace('__API_ORIGIN__', apiOrigin),
      },
    ],
    build: { outDir: 'dist', sourcemap: false },
  };
});
