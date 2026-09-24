import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
    exclude: ['**/*.live.test.ts', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
