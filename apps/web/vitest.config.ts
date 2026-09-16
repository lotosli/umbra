import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}', 'tooling/**/*.test.ts'],
    setupFiles: ['./tests/setup.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}', 'tooling/**/*.ts'],
      exclude: ['**/*.test.{ts,tsx}', 'src/routeTree.gen.ts', 'src/content/*.generated.ts', 'src/vite-env.d.ts'],
      reporter: ['text', 'json-summary', 'lcov'],
      thresholds: { lines: 90 },
    },
  },
});
