import { defineConfig } from 'vitest/config';

/**
 * Config for the OPT-IN live-network verification suite
 * (`npm run test:live`). Not part of the default `npm test` run, which must
 * stay hermetic/offline (see vitest.config.ts). This exists purely to let a
 * human/CI job manually confirm the real HttpEpssClient/HttpKevClient still
 * work against the real live endpoints, on demand, without ever being a
 * silent dependency of the standard test/CI run.
 */
export default defineConfig({
  test: {
    include: ['test/live/**/*.live.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
  },
});
