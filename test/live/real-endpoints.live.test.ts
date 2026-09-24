import { describe, expect, it } from 'vitest';
import { HttpEpssClient } from '../../src/sources/epss.js';
import { HttpKevClient } from '../../src/sources/kev.js';

/**
 * OPT-IN live-network verification. Run explicitly with `npm run test:live`
 * - this file is excluded from the default `npm test` run (see
 * vitest.config.ts / vitest.live.config.ts) so CI and normal development
 * never depend on network access. Its only purpose is to let a human
 * confirm, on demand, that the real HttpEpssClient/HttpKevClient still
 * work against the real live FIRST.org EPSS API and the real live CISA KEV
 * feed - the same clients the CLI uses by default when --epss-file/
 * --kev-file are not given.
 */
describe('live network: real EPSS + KEV endpoints', () => {
  it('fetches a real EPSS score for a well-known CVE from the live FIRST.org API', async () => {
    const client = new HttpEpssClient();
    const [entry] = await client.fetchScores(['CVE-2021-44228']);
    expect(entry?.cve).toBe('CVE-2021-44228');
    expect(entry?.epss).toBeGreaterThan(0);
    expect(entry?.epss).toBeLessThanOrEqual(1);
  });

  it('fetches the real, live CISA KEV catalog and finds a well-known entry in it', async () => {
    const client = new HttpKevClient();
    const catalog = await client.fetchCatalog();
    expect(catalog.length).toBeGreaterThan(500);
    expect(catalog.some((e) => e.cveID === 'CVE-2021-44228')).toBe(true);
  });
});
