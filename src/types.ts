/**
 * Core domain types shared across parsers, data sources, scoring, and the CLI.
 */

/** Severity levels normalized across scanner formats. */
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

/** Which scanner format a finding was normalized from. */
export type ScannerName = 'trivy' | 'grype';

/**
 * A single vulnerability finding, normalized from a scanner report into a
 * scanner-agnostic shape. All parsers in `src/parsers/*` produce this type.
 */
export interface ScannerFinding {
  /** CVE identifier, e.g. "CVE-2021-44228". May also be a GHSA id if the
   * scanner reported no CVE alias; callers should be aware EPSS/KEV lookups
   * only match on CVE ids. */
  readonly id: string;
  /** The scan target the finding was reported against (image name, repo
   * path, or artifact name) as reported by the scanner. Used to match
   * asset-criticality rules. */
  readonly target: string;
  /** Affected package/artifact name, if the scanner reports one. */
  readonly packageName?: string;
  readonly installedVersion?: string;
  readonly fixedVersion?: string;
  /** Normalized severity bucket. */
  readonly severity: Severity;
  /** CVSS base score (0-10) if the scanner reported one. */
  readonly cvssScore?: number;
  readonly title?: string;
  readonly description?: string;
  /** Which scanner/parser produced this finding. */
  readonly sourceScanner: ScannerName;
}

/** A single EPSS (Exploit Prediction Scoring System) record for one CVE. */
export interface EpssEntry {
  readonly cve: string;
  /** Probability of exploitation in the next 30 days, in [0, 1]. */
  readonly epss: number;
  /** Percentile rank among all scored CVEs, in [0, 1]. */
  readonly percentile: number;
  /** The EPSS model score date (YYYY-MM-DD), as published upstream. */
  readonly date: string;
}

/** A single entry from the CISA Known Exploited Vulnerabilities catalog. */
export interface KevEntry {
  readonly cveID: string;
  readonly vendorProject: string;
  readonly product: string;
  readonly vulnerabilityName: string;
  readonly dateAdded: string;
  readonly shortDescription: string;
  readonly requiredAction: string;
  readonly dueDate: string;
  readonly knownRansomwareCampaignUse: string;
}

/** Asset-criticality tag supplied by the user for a scan target. */
export type CriticalityTag = 'critical' | 'high' | 'medium' | 'low';

/**
 * User-supplied configuration mapping scan targets to a business-criticality
 * tag. Matched against `ScannerFinding.target` (see src/merge/assets.ts).
 */
export interface AssetCriticalityConfig {
  /** Criticality applied to any target that matches no rule below. */
  readonly defaultCriticality: CriticalityTag;
  readonly assets: readonly AssetCriticalityRule[];
}

export interface AssetCriticalityRule {
  /** Exact string or glob pattern (`*` wildcard) matched against
   * `ScannerFinding.target`. */
  readonly match: string;
  readonly criticality: CriticalityTag;
}

/** The four weighted inputs behind every score, and their contribution. */
export interface ScoreBreakdown {
  readonly kevListed: boolean;
  readonly kevComponent: number;
  readonly epssScore: number;
  readonly epssComponent: number;
  readonly severity: Severity;
  readonly severityComponent: number;
  readonly assetCriticality: CriticalityTag;
  readonly assetComponent: number;
  readonly weights: {
    readonly kev: number;
    readonly epss: number;
    readonly severity: number;
    readonly asset: number;
  };
  /** Sum of the four components above, clamped to [0, 100]. */
  readonly total: number;
}

/** A scanner finding enriched with EPSS/KEV/asset data and a final score. */
export interface ScoredFinding extends ScannerFinding {
  readonly score: ScoreBreakdown;
}
