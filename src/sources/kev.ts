import { readFile } from 'node:fs/promises';
import type { KevEntry } from '../types.js';
import { realFetch, type FetchLike } from './httpFetcher.js';

/**
 * CISA Known Exploited Vulnerabilities (KEV) catalog data source.
 *
 * Real upstream: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * (documented at https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
 * a JSON document CISA updates as vulnerabilities are confirmed to be
 * actively exploited in the wild. Presence in this catalog is the single
 * highest-weighted signal in VulnTriage's scoring formula (see
 * src/scoring/score.ts) - it is the difference between "theoretically
 * severe" and "currently being used to break into real systems".
 *
 * `test/fixtures/kev-snapshot.json` ships a small, real, trimmed subset of
 * this catalog (a handful of real entries, same schema, pulled live) so
 * tests never need network access.
 */

export interface KevClient {
  /** Fetch the full KEV catalog. VulnTriage always loads the whole catalog
   * (not filtered by CVE) since CISA does not offer a filtered-query API -
   * it is one JSON document, currently a few thousand entries, that
   * comfortably fits in memory. */
  fetchCatalog(): Promise<KevEntry[]>;
}

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface CisaKevApiEntry {
  readonly cveID: string;
  readonly vendorProject?: string;
  readonly product?: string;
  readonly vulnerabilityName?: string;
  readonly dateAdded?: string;
  readonly shortDescription?: string;
  readonly requiredAction?: string;
  readonly dueDate?: string;
  readonly knownRansomwareCampaignUse?: string;
}

interface CisaKevApiResponse {
  readonly title?: string;
  readonly catalogVersion?: string;
  readonly dateReleased?: string;
  readonly count?: number;
  readonly vulnerabilities?: readonly CisaKevApiEntry[];
}

function normalizeEntry(raw: CisaKevApiEntry): KevEntry {
  return {
    cveID: raw.cveID.toUpperCase(),
    vendorProject: raw.vendorProject ?? '',
    product: raw.product ?? '',
    vulnerabilityName: raw.vulnerabilityName ?? '',
    dateAdded: raw.dateAdded ?? '',
    shortDescription: raw.shortDescription ?? '',
    requiredAction: raw.requiredAction ?? '',
    dueDate: raw.dueDate ?? '',
    knownRansomwareCampaignUse: raw.knownRansomwareCampaignUse ?? 'Unknown',
  };
}

/** Real KEV client: fetches the live CISA KEV catalog JSON. */
export class HttpKevClient implements KevClient {
  constructor(
    private readonly fetchImpl: FetchLike = realFetch,
    private readonly url: string = CISA_KEV_URL,
  ) {}

  async fetchCatalog(): Promise<KevEntry[]> {
    const response = await this.fetchImpl(this.url);
    if (!response.ok) {
      throw new Error(`CISA KEV fetch failed: HTTP ${response.status} (${this.url})`);
    }
    const body = (await response.json()) as CisaKevApiResponse;
    return (body.vulnerabilities ?? []).map(normalizeEntry);
  }
}

/** Snapshot-backed KEV client for offline/hermetic use (tests, air-gapped
 * environments, or `--kev-file` on the CLI). */
export class FileKevClient implements KevClient {
  constructor(private readonly filePath: string) {}

  async fetchCatalog(): Promise<KevEntry[]> {
    const text = await readFile(this.filePath, 'utf8');
    const parsed = JSON.parse(text) as CisaKevApiResponse;
    return (parsed.vulnerabilities ?? []).map(normalizeEntry);
  }
}

/** Build a CVE -> KevEntry lookup map (keys upper-cased for
 * case-insensitive matching against scanner-reported CVE ids). */
export function buildKevIndex(entries: readonly KevEntry[]): Map<string, KevEntry> {
  const index = new Map<string, KevEntry>();
  for (const entry of entries) {
    index.set(entry.cveID.toUpperCase(), entry);
  }
  return index;
}
