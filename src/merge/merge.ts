import type { AssetCriticalityConfig, EpssEntry, KevEntry, ScannerFinding, ScoredFinding } from '../types.js';
import { scoreFinding } from '../scoring/score.js';
import { matchAssetCriticality } from './assets.js';

export interface MergeInputs {
  readonly findings: readonly ScannerFinding[];
  readonly epssIndex: ReadonlyMap<string, EpssEntry>;
  readonly kevIndex: ReadonlyMap<string, KevEntry>;
  readonly assetConfig?: AssetCriticalityConfig;
}

/** Merge normalized scanner findings with EPSS/KEV data and asset
 * criticality, producing a scored (but not yet ranked/sorted) finding for
 * each input. EPSS lookups default to 0 ("no known exploitation
 * probability data") when a CVE has no EPSS record - see README
 * Limitations for why that is the conservative choice, not "assume
 * dangerous". */
export function mergeAndScore(inputs: MergeInputs): ScoredFinding[] {
  return inputs.findings.map((finding) => {
    const key = finding.id.toUpperCase();
    const epssEntry = inputs.epssIndex.get(key);
    const kevListed = inputs.kevIndex.has(key);
    const assetCriticality = inputs.assetConfig
      ? matchAssetCriticality(finding.target, inputs.assetConfig)
      : undefined;

    const score = scoreFinding({
      finding,
      epssScore: epssEntry?.epss ?? 0,
      kevListed,
      ...(assetCriticality !== undefined ? { assetCriticality } : {}),
    });

    return { ...finding, score };
  });
}

/** Sort scored findings into VulnTriage's final ranked order: highest total
 * score first. Ties are broken deterministically by CVE id then target so
 * output ordering never depends on input order or object identity - the
 * same inputs always produce byte-identical output. */
export function rankFindings(scored: readonly ScoredFinding[]): ScoredFinding[] {
  return [...scored].sort((a, b) => {
    if (b.score.total !== a.score.total) return b.score.total - a.score.total;
    if (a.id !== b.id) return a.id.localeCompare(b.id);
    return a.target.localeCompare(b.target);
  });
}
