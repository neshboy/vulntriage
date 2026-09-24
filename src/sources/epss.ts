import { readFile } from 'node:fs/promises';
import type { EpssEntry } from '../types.js';
import { realFetch, type FetchLike } from './httpFetcher.js';

/**
 * EPSS (Exploit Prediction Scoring System) data source.
 *
 * Real upstream: the FIRST.org EPSS API (https://www.first.org/epss/api),
 * which serves the same daily-published scores as the bulk CSV at
 * https://epss.cyentia.com/epss_scores-current.csv.gz without requiring
 * gzip decompression. VulnTriage queries it by explicit CVE list rather
 * than downloading the full ~250k-row daily CSV, since a triage run only
 * ever needs scores for the CVEs actually present in the scanner report.
 *
 * `test/fixtures/epss-snapshot.csv` ships a small, real, trimmed-down copy
 * of the *bulk CSV format* (same columns FIRST publishes: cve,epss,
 * percentile, preceded by the real `#model_version:...,score_date:...`
 * comment line) so the parser is exercised against the real on-disk format
 * too, and so tests never need network access.
 */

export interface EpssClient {
  /** Fetch EPSS scores for the given CVE ids. CVEs with no EPSS record
   * (e.g. not yet scored, or not a real CVE) are simply omitted from the
   * result rather than erroring. */
  fetchScores(cves: readonly string[]): Promise<EpssEntry[]>;
}

const FIRST_EPSS_API_BASE = 'https://api.first.org/data/v1/epss';
/** FIRST's API pages results; requesting more CVEs than this in one call
 * risks silent truncation, so requests are chunked to this size. */
const DEFAULT_BATCH_SIZE = 100;

interface FirstEpssApiRow {
  readonly cve: string;
  readonly epss: string;
  readonly percentile: string;
  readonly date: string;
}

interface FirstEpssApiResponse {
  readonly status?: string;
  readonly data?: readonly FirstEpssApiRow[];
}

function chunk<T>(items: readonly T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

/** Real EPSS client: queries the live FIRST.org EPSS API. */
export class HttpEpssClient implements EpssClient {
  constructor(
    private readonly fetchImpl: FetchLike = realFetch,
    private readonly baseUrl: string = FIRST_EPSS_API_BASE,
    private readonly batchSize: number = DEFAULT_BATCH_SIZE,
  ) {}

  async fetchScores(cves: readonly string[]): Promise<EpssEntry[]> {
    const unique = [...new Set(cves.map((c) => c.toUpperCase()))];
    const results: EpssEntry[] = [];

    for (const batch of chunk(unique, this.batchSize)) {
      const url = `${this.baseUrl}?cve=${batch.join(',')}&limit=${batch.length}`;
      const response = await this.fetchImpl(url);
      if (!response.ok) {
        throw new Error(`EPSS API request failed: HTTP ${response.status} (${url})`);
      }
      const body = (await response.json()) as FirstEpssApiResponse;
      for (const row of body.data ?? []) {
        results.push({
          cve: row.cve.toUpperCase(),
          epss: Number.parseFloat(row.epss),
          percentile: Number.parseFloat(row.percentile),
          date: row.date,
        });
      }
    }

    return results;
  }
}

/** Parse the real EPSS bulk-CSV format published at
 * epss.cyentia.com/epss_scores-current.csv.gz (after gunzip): a leading
 * `#model_version:...,score_date:...` comment line, a `cve,epss,percentile`
 * header, then one row per CVE. */
export function parseEpssCsv(csvText: string): EpssEntry[] {
  const lines = csvText.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const dataLines = lines.filter((line) => !line.startsWith('#'));
  if (dataLines.length === 0) return [];

  const header = dataLines[0]?.split(',').map((h) => h.trim().toLowerCase()) ?? [];
  const cveIdx = header.indexOf('cve');
  const epssIdx = header.indexOf('epss');
  const percentileIdx = header.indexOf('percentile');
  if (cveIdx === -1 || epssIdx === -1) {
    throw new Error('EPSS CSV missing required "cve"/"epss" columns');
  }

  // The model_version comment line carries the score date, e.g.
  // "#model_version:v2025.03.14,score_date:2026-09-23T00:00:00+0000"
  const commentLine = lines.find((line) => line.startsWith('#'));
  const dateMatch = commentLine?.match(/score_date:(\S+)/);
  const scoreDate = dateMatch?.[1]?.slice(0, 10) ?? '';

  const entries: EpssEntry[] = [];
  for (const line of dataLines.slice(1)) {
    const cols = line.split(',');
    const cve = cols[cveIdx]?.trim();
    const epss = cols[epssIdx]?.trim();
    if (!cve || !epss) continue;
    entries.push({
      cve: cve.toUpperCase(),
      epss: Number.parseFloat(epss),
      percentile: percentileIdx >= 0 ? Number.parseFloat(cols[percentileIdx]?.trim() ?? '0') : 0,
      date: scoreDate,
    });
  }
  return entries;
}

/** Snapshot-backed EPSS client for offline/hermetic use (tests, air-gapped
 * environments, or `--epss-file` on the CLI). Loads the entire snapshot
 * once and serves lookups from memory. */
export class FileEpssClient implements EpssClient {
  private cachedEntries: EpssEntry[] | undefined;

  constructor(private readonly filePath: string) {}

  async fetchScores(cves: readonly string[]): Promise<EpssEntry[]> {
    const all = await this.loadAll();
    const wanted = new Set(cves.map((c) => c.toUpperCase()));
    return all.filter((entry) => wanted.has(entry.cve));
  }

  private async loadAll(): Promise<EpssEntry[]> {
    if (!this.cachedEntries) {
      const text = await readFile(this.filePath, 'utf8');
      this.cachedEntries = parseEpssCsv(text);
    }
    return this.cachedEntries;
  }
}

/** Build a CVE -> EpssEntry lookup map (keys upper-cased for
 * case-insensitive matching against scanner-reported CVE ids). */
export function buildEpssIndex(entries: readonly EpssEntry[]): Map<string, EpssEntry> {
  const index = new Map<string, EpssEntry>();
  for (const entry of entries) {
    index.set(entry.cve.toUpperCase(), entry);
  }
  return index;
}
