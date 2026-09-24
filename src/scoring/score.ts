import type {
  CriticalityTag,
  KevEntry,
  ScannerFinding,
  ScoreBreakdown,
  Severity,
} from '../types.js';

/**
 * VulnTriage scoring formula.
 *
 * total = KEV_WEIGHT * kevComponent
 *       + EPSS_WEIGHT * epssComponent
 *       + SEVERITY_WEIGHT * severityComponent
 *       + ASSET_WEIGHT * assetComponent
 *
 * All four weights are constants that sum to 100, and every component is
 * normalized to [0, 1], so `total` lands in [0, 100] by construction (no
 * clamping is actually needed, but we clamp defensively in case of bad
 * input, e.g. an out-of-range CVSS score from a malformed report).
 *
 * The weights are deliberately KEV-dominant: a finding on the real CISA
 * Known Exploited Vulnerabilities catalog gets close to half its maximum
 * possible score from that fact alone, before severity or asset criticality
 * are even considered. This is the entire point of the tool: a CVE that is
 * *confirmed, currently* being exploited in the wild should almost always
 * outrank a CVE that merely has a high CVSS score but no evidence of actual
 * exploitation. See README.md "Scoring formula" for the worked example and
 * `src/scoring/score.test.ts` for the executable proof.
 */
export const KEV_WEIGHT = 45;
export const EPSS_WEIGHT = 25;
export const SEVERITY_WEIGHT = 15;
export const ASSET_WEIGHT = 15;

/** Severity -> normalized [0, 1] score, used only when the scanner did not
 * report a numeric CVSS base score. Values chosen so CRITICAL/HIGH/MEDIUM/
 * LOW land at the same relative spacing CVSS itself uses (roughly 9/7/5/3
 * on a 0-10 scale). */
const SEVERITY_FALLBACK_SCORE: Record<Severity, number> = {
  CRITICAL: 0.9,
  HIGH: 0.7,
  MEDIUM: 0.5,
  LOW: 0.3,
  UNKNOWN: 0.1,
};

/** Asset-criticality tag -> normalized [0, 1] score. */
const ASSET_CRITICALITY_SCORE: Record<CriticalityTag, number> = {
  critical: 1.0,
  high: 0.75,
  medium: 0.5,
  low: 0.25,
};

/** Default criticality score applied when no tag is available at all
 * (e.g. no asset-criticality config was supplied). Matches "medium" so an
 * untagged asset is neither inflated nor unfairly buried. */
export const DEFAULT_ASSET_CRITICALITY_SCORE = 0.5;

function clamp01(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(1, Math.max(0, n));
}

/** Normalize a finding's severity signal to [0, 1]. Prefers a numeric CVSS
 * base score (score / 10) when present, since it is more granular than the
 * five-bucket severity label; falls back to the severity bucket otherwise. */
export function normalizeSeverity(finding: Pick<ScannerFinding, 'severity' | 'cvssScore'>): number {
  if (typeof finding.cvssScore === 'number' && Number.isFinite(finding.cvssScore)) {
    return clamp01(finding.cvssScore / 10);
  }
  return SEVERITY_FALLBACK_SCORE[finding.severity];
}

/** Normalize an asset-criticality tag to [0, 1]. */
export function normalizeAssetCriticality(tag: CriticalityTag | undefined): number {
  if (tag === undefined) return DEFAULT_ASSET_CRITICALITY_SCORE;
  return ASSET_CRITICALITY_SCORE[tag];
}

export interface ScoreInputs {
  readonly finding: Pick<ScannerFinding, 'severity' | 'cvssScore'>;
  /** EPSS probability in [0, 1]. Pass 0 when no EPSS record exists for the
   * CVE (conservative default - see README Limitations). */
  readonly epssScore: number;
  /** Whether the CVE appears in the CISA KEV catalog. */
  readonly kevListed: boolean;
  /** The matched asset-criticality tag, if any. */
  readonly assetCriticality?: CriticalityTag;
}

/** Compute the full, explainable score breakdown for one finding. This is
 * the single source of truth for the ranking formula - the CLI's "why this
 * matters" output is a direct rendering of this object, not a re-derivation
 * of it. */
export function scoreFinding(inputs: ScoreInputs): ScoreBreakdown {
  const kevComponent = inputs.kevListed ? 1 : 0;
  const epssComponent = clamp01(inputs.epssScore);
  const severityComponent = normalizeSeverity(inputs.finding);
  const assetComponent = normalizeAssetCriticality(inputs.assetCriticality);

  const total = clamp01to100(
    KEV_WEIGHT * kevComponent +
      EPSS_WEIGHT * epssComponent +
      SEVERITY_WEIGHT * severityComponent +
      ASSET_WEIGHT * assetComponent,
  );

  return {
    kevListed: inputs.kevListed,
    kevComponent: round(KEV_WEIGHT * kevComponent),
    epssScore: epssComponent,
    epssComponent: round(EPSS_WEIGHT * epssComponent),
    severity: inputs.finding.severity,
    severityComponent: round(SEVERITY_WEIGHT * severityComponent),
    assetCriticality: inputs.assetCriticality ?? 'medium',
    assetComponent: round(ASSET_WEIGHT * assetComponent),
    weights: {
      kev: KEV_WEIGHT,
      epss: EPSS_WEIGHT,
      severity: SEVERITY_WEIGHT,
      asset: ASSET_WEIGHT,
    },
    total: round(total),
  };
}

function clamp01to100(n: number): number {
  if (Number.isNaN(n)) return 0;
  return Math.min(100, Math.max(0, n));
}

/** Round to 2 decimal places for stable, readable output (scores are
 * inherently a sum of well-defined fractions of integer weights, so 2
 * decimals never loses meaningful precision). */
function round(n: number): number {
  return Math.round(n * 100) / 100;
}

/** Convenience: does a KEV catalog contain this CVE? Catalog lookups are
 * intentionally case-insensitive on the id since scanners occasionally
 * differ in casing. */
export function isKevListed(cveId: string, kevByCve: ReadonlyMap<string, KevEntry>): boolean {
  return kevByCve.has(cveId.toUpperCase());
}
