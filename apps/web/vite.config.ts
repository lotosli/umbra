import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { cloudflare } from '@cloudflare/vite-plugin';
import { tanstackStart } from '@tanstack/react-start/plugin/vite';
import { fumadocsMdx } from 'fumadocs-mdx/vite';

export default defineConfig({
  plugins: [
    fumadocsMdx(),
    cloudflare({ viteEnvironment: { name: 'ssr' } }),
    tanstackStart(),
    react(),
    tailwindcss(),
  ],
  server: { port: 3000 },
  preview: { port: 3000 },
});
