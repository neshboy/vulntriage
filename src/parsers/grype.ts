import type { ScannerFinding, Severity } from '../types.js';

/**
 * Parser for Anchore Grype's native JSON report format
 * (`grype <target> -o json`). Schema reference:
 * https://github.com/anchore/grype#grype-schema (schema/json/schema-*.json
 * in the grype repo). Only the fields VulnTriage needs are typed below.
 */

interface GrypeCvssMetrics {
  readonly baseScore?: number;
}

interface GrypeCvss {
  readonly version?: string;
  readonly metrics?: GrypeCvssMetrics;
}

interface GrypeFix {
  readonly versions?: readonly string[];
  readonly state?: string;
}

interface GrypeVulnerability {
  readonly id: string;
  readonly severity?: string;
  readonly description?: string;
  readonly cvss?: readonly GrypeCvss[];
  readonly fix?: GrypeFix;
}

interface GrypeArtifact {
  readonly name?: string;
  readonly version?: string;
}

interface GrypeMatch {
  readonly vulnerability: GrypeVulnerability;
  readonly artifact?: GrypeArtifact;
}

interface GrypeTarget {
  readonly userInput?: string;
}

interface GrypeSource {
  readonly type?: string;
  readonly target?: GrypeTarget | string;
}

export interface GrypeReport {
  readonly matches?: readonly GrypeMatch[];
  readonly source?: GrypeSource;
}

/** Grype's own severity vocabulary, ordered Unknown < Negligible < Low <
 * Medium < High < Critical. VulnTriage's Severity type has no "Negligible"
 * bucket (see README Limitations), so it is folded into UNKNOWN rather than
 * LOW - Negligible findings are explicitly *below* Low in Grype's own
 * ordering, and UNKNOWN carries the lowest severity-component weight. */
const GRYPE_SEVERITY_MAP: Readonly<Record<string, Severity>> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NEGLIGIBLE: 'UNKNOWN',
  UNKNOWN: 'UNKNOWN',
};

function normalizeSeverityLabel(raw: string | undefined): Severity {
  const upper = (raw ?? '').toUpperCase();
  return GRYPE_SEVERITY_MAP[upper] ?? 'UNKNOWN';
}

/** Pick the highest CVSS base score, preferring v3.x entries over v2 when
 * both are present (mirrors the Trivy parser's preference). */
function extractCvssScore(cvss: readonly GrypeCvss[] | undefined): number | undefined {
  if (!cvss || cvss.length === 0) return undefined;

  const scored = cvss
    .map((c) => ({ version: c.version ?? '', score: c.metrics?.baseScore }))
    .filter((c): c is { version: string; score: number } => typeof c.score === 'number' && Number.isFinite(c.score));
  if (scored.length === 0) return undefined;

  const v3 = scored.filter((c) => c.version.startsWith('3'));
  const pool = v3.length > 0 ? v3 : scored;
  return Math.max(...pool.map((c) => c.score));
}

function extractTarget(source: GrypeSource | undefined): string | undefined {
  if (!source?.target) return undefined;
  if (typeof source.target === 'string') return source.target;
  return source.target.userInput;
}

/** Parse a Grype JSON report (already `JSON.parse`d) into VulnTriage's
 * normalized `ScannerFinding[]`. Grype reports scan exactly one target per
 * run (`source.target.userInput`, e.g. an image reference or directory
 * path), so every finding in a report shares the same `target`; falls back
 * to the affected package name if `source` is absent (e.g. hand-trimmed
 * fixtures or SBOM-only invocations). */
export function parseGrypeReport(report: GrypeReport): ScannerFinding[] {
  const reportTarget = extractTarget(report.source);
  const findings: ScannerFinding[] = [];

  for (const match of report.matches ?? []) {
    const vuln = match.vulnerability;
    const cvssScore = extractCvssScore(vuln.cvss);
    const fixedVersion =
      vuln.fix?.state === 'fixed' && vuln.fix.versions && vuln.fix.versions.length > 0
        ? vuln.fix.versions[0]
        : undefined;
    const target = reportTarget ?? match.artifact?.name ?? 'unknown-target';

    const finding: ScannerFinding = {
      id: vuln.id,
      target,
      severity: normalizeSeverityLabel(vuln.severity),
      sourceScanner: 'grype',
      ...(match.artifact?.name !== undefined ? { packageName: match.artifact.name } : {}),
      ...(match.artifact?.version !== undefined ? { installedVersion: match.artifact.version } : {}),
      ...(fixedVersion !== undefined ? { fixedVersion } : {}),
      ...(cvssScore !== undefined ? { cvssScore } : {}),
      ...(vuln.description !== undefined ? { description: vuln.description } : {}),
    };
    findings.push(finding);
  }

  return findings;
}

/** Parse a raw JSON string of a Grype report. Throws a descriptive error if
 * the input is not valid JSON or is obviously not a Grype report. */
export function parseGrypeReportText(text: string): ScannerFinding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`Failed to parse Grype report as JSON: ${(err as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || !('matches' in parsed)) {
    throw new Error(
      'Input does not look like a Grype JSON report (missing top-level "matches" array). ' +
        'Generate one with `grype <target> -o json > report.json`.',
    );
  }
  return parseGrypeReport(parsed as GrypeReport);
}
