import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { FileKevClient, HttpKevClient, buildKevIndex } from './kev.js';
import type { FetchLike } from './httpFetcher.js';

const fixturePath = fileURLToPath(new URL('../../test/fixtures/kev-snapshot.json', import.meta.url));

describe('FileKevClient', () => {
  it('loads the real trimmed KEV snapshot', async () => {
    const client = new FileKevClient(fixturePath);
    const entries = await client.fetchCatalog();

    expect(entries.length).toBe(7);
    const log4shell = entries.find((e) => e.cveID === 'CVE-2021-44228');
    expect(log4shell?.vulnerabilityName).toMatch(/Log4j2/i);
    expect(log4shell?.knownRansomwareCampaignUse).toBe('Known');
  });

  it('produces an index from which a real, genuinely non-KEV CVE (CVE-2023-38545) is absent', async () => {
    const client = new FileKevClient(fixturePath);
    const index = buildKevIndex(await client.fetchCatalog());
    expect(index.has('CVE-2023-38545')).toBe(false);
    expect(index.has('CVE-2021-44228')).toBe(true);
  });
});

describe('HttpKevClient', () => {
  it('fetches the real CISA KEV JSON shape via an injected fetch, without any real network access', async () => {
    const fakeFetch: FetchLike = vi.fn(async (url: string | URL | Request) => {
      expect(String(url)).toBe('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          title: 'CISA Catalog of Known Exploited Vulnerabilities',
          catalogVersion: '2026.09.23',
          count: 1,
          vulnerabilities: [
            {
              cveID: 'cve-2021-44228',
              vendorProject: 'Apache',
              product: 'Log4j2',
              vulnerabilityName: 'Apache Log4j2 RCE',
              dateAdded: '2021-12-10',
              shortDescription: 'desc',
              requiredAction: 'action',
              dueDate: '2021-12-24',
              knownRansomwareCampaignUse: 'Known',
            },
          ],
        }),
      } as Response;
    }) as unknown as FetchLike;

    const client = new HttpKevClient(fakeFetch);
    const entries = await client.fetchCatalog();

    expect(fakeFetch).toHaveBeenCalledTimes(1);
    expect(entries).toHaveLength(1);
    // cveID is normalized to upper-case regardless of upstream casing.
    expect(entries[0]?.cveID).toBe('CVE-2021-44228');
  });

  it('throws a descriptive error on a non-OK HTTP response', async () => {
    const fakeFetch: FetchLike = vi.fn(async () => ({ ok: false, status: 500 }) as unknown as Response) as unknown as FetchLike;
    const client = new HttpKevClient(fakeFetch);
    await expect(client.fetchCatalog()).rejects.toThrow(/HTTP 500/);
  });

  it('defaults missing optional fields to safe fallbacks', async () => {
    const fakeFetch: FetchLike = vi.fn(async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({ vulnerabilities: [{ cveID: 'CVE-2000-0001' }] }),
      }) as unknown as Response,
    ) as unknown as FetchLike;
    const client = new HttpKevClient(fakeFetch);
    const [entry] = await client.fetchCatalog();
    expect(entry?.knownRansomwareCampaignUse).toBe('Unknown');
    expect(entry?.vendorProject).toBe('');
  });
});

describe('buildKevIndex', () => {
  it('keys entries by upper-cased CVE id', () => {
    const index = buildKevIndex([
      {
        cveID: 'cve-2021-44228',
        vendorProject: 'Apache',
        product: 'Log4j2',
        vulnerabilityName: 'x',
        dateAdded: '2021-12-10',
        shortDescription: '',
        requiredAction: '',
        dueDate: '',
        knownRansomwareCampaignUse: 'Known',
      },
    ]);
    expect(index.has('CVE-2021-44228')).toBe(true);
  });
});
