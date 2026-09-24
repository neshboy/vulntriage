import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { FileEpssClient, HttpEpssClient, buildEpssIndex, parseEpssCsv } from './epss.js';
import type { FetchLike } from './httpFetcher.js';

const fixturePath = fileURLToPath(new URL('../../test/fixtures/epss-snapshot.csv', import.meta.url));

describe('parseEpssCsv', () => {
  it('parses the real EPSS bulk-CSV format (comment header + cve,epss,percentile rows)', () => {
    const csv = [
      '#model_version:v2026.06.15,score_date:2026-09-23T12:00:20Z',
      'cve,epss,percentile',
      'CVE-2021-44228,0.99999,1.0',
      'CVE-2024-0001,0.00949,0.59729',
    ].join('\n');

    const entries = parseEpssCsv(csv);
    expect(entries).toEqual([
      { cve: 'CVE-2021-44228', epss: 0.99999, percentile: 1.0, date: '2026-09-23' },
      { cve: 'CVE-2024-0001', epss: 0.00949, percentile: 0.59729, date: '2026-09-23' },
    ]);
  });

  it('parses the real trimmed snapshot fixture without error', async () => {
    const { readFile } = await import('node:fs/promises');
    const text = await readFile(fixturePath, 'utf8');
    const entries = parseEpssCsv(text);
    expect(entries.length).toBeGreaterThanOrEqual(8);
    expect(entries.find((e) => e.cve === 'CVE-2021-44228')?.epss).toBeCloseTo(0.99999);
  });

  it('returns an empty array for empty input', () => {
    expect(parseEpssCsv('')).toEqual([]);
  });

  it('throws if the required cve/epss columns are missing', () => {
    expect(() => parseEpssCsv('foo,bar\n1,2')).toThrow(/missing required/);
  });
});

describe('FileEpssClient', () => {
  it('loads the real trimmed snapshot and filters by requested CVEs', async () => {
    const client = new FileEpssClient(fixturePath);
    const scores = await client.fetchScores(['CVE-2021-44228', 'CVE-2023-38545', 'CVE-9999-0001']);

    const byCve = buildEpssIndex(scores);
    expect(byCve.get('CVE-2021-44228')?.epss).toBeCloseTo(0.99999);
    expect(byCve.get('CVE-2023-38545')?.epss).toBeCloseTo(0.78483);
    // CVE-9999-0001 has no real EPSS record and must simply be absent, not zero-filled.
    expect(byCve.has('CVE-9999-0001')).toBe(false);
  });

  it('matches CVE ids case-insensitively', async () => {
    const client = new FileEpssClient(fixturePath);
    const scores = await client.fetchScores(['cve-2021-44228']);
    expect(scores).toHaveLength(1);
  });
});

describe('HttpEpssClient', () => {
  it('queries the FIRST.org EPSS API shape via an injected fetch, without any real network access', async () => {
    const fakeFetch: FetchLike = vi.fn(async (url: string | URL | Request) => {
      expect(String(url)).toContain('api.first.org/data/v1/epss');
      expect(String(url)).toContain('CVE-2021-44228');
      return {
        ok: true,
        status: 200,
        json: async () => ({
          status: 'OK',
          data: [{ cve: 'CVE-2021-44228', epss: '0.99999', percentile: '1.00000', date: '2026-09-23' }],
        }),
      } as Response;
    }) as unknown as FetchLike;

    const client = new HttpEpssClient(fakeFetch);
    const scores = await client.fetchScores(['CVE-2021-44228']);

    expect(fakeFetch).toHaveBeenCalledTimes(1);
    expect(scores).toEqual([{ cve: 'CVE-2021-44228', epss: 0.99999, percentile: 1.0, date: '2026-09-23' }]);
  });

  it('chunks requests to avoid exceeding the API batch size', async () => {
    const calls: string[] = [];
    const fakeFetch: FetchLike = vi.fn(async (url: string | URL | Request) => {
      calls.push(String(url));
      return { ok: true, status: 200, json: async () => ({ data: [] }) } as unknown as Response;
    }) as unknown as FetchLike;

    const client = new HttpEpssClient(fakeFetch, undefined, 2);
    await client.fetchScores(['CVE-1', 'CVE-2', 'CVE-3']);

    expect(calls).toHaveLength(2);
  });

  it('throws a descriptive error on a non-OK HTTP response', async () => {
    const fakeFetch: FetchLike = vi.fn(async () => ({ ok: false, status: 503 }) as unknown as Response) as unknown as FetchLike;
    const client = new HttpEpssClient(fakeFetch);
    await expect(client.fetchScores(['CVE-2021-44228'])).rejects.toThrow(/HTTP 503/);
  });

  it('deduplicates and case-normalizes requested CVE ids', async () => {
    let requestedUrl = '';
    const fakeFetch: FetchLike = vi.fn(async (url: string | URL | Request) => {
      requestedUrl = String(url);
      return { ok: true, status: 200, json: async () => ({ data: [] }) } as unknown as Response;
    }) as unknown as FetchLike;

    const client = new HttpEpssClient(fakeFetch);
    await client.fetchScores(['cve-2021-44228', 'CVE-2021-44228']);
    expect(requestedUrl).toContain('cve=CVE-2021-44228&');
    expect(requestedUrl).not.toContain(',');
  });
});

describe('buildEpssIndex', () => {
  it('keys entries by upper-cased CVE id', () => {
    const index = buildEpssIndex([{ cve: 'cve-2021-44228', epss: 0.5, percentile: 0.5, date: '2026-01-01' }]);
    expect(index.get('CVE-2021-44228')?.epss).toBe(0.5);
  });
});
