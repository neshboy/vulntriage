import type { ScannerFinding, Severity } from '../types.js';

/**
 * Parser for Trivy's native JSON report format (`trivy image -f json ...`,
 * `trivy fs -f json ...`, etc.). Schema reference:
 * https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/#json
 *
 * Only the fields VulnTriage actually needs are typed below; Trivy's real
 * output has many more (Layer, DataSource, References, ...) that we
 * intentionally ignore.
 */

interface TrivyCvssVendorScore {
  readonly V2Score?: number;
  readonly V3Score?: number;
}

interface TrivyVulnerability {
  readonly VulnerabilityID: string;
  readonly PkgName?: string;
  readonly InstalledVersion?: string;
  readonly FixedVersion?: string;
  readonly Severity?: string;
  readonly Title?: string;
  readonly Description?: string;
  readonly CVSS?: Record<string, TrivyCvssVendorScore>;
}

interface TrivyResult {
  readonly Target?: string;
  readonly Class?: string;
  readonly Type?: string;
  readonly Vulnerabilities?: readonly TrivyVulnerability[];
}

export interface TrivyReport {
  readonly SchemaVersion?: number;
  readonly ArtifactName?: string;
  readonly ArtifactType?: string;
  readonly Results?: readonly TrivyResult[];
}

const KNOWN_SEVERITIES: ReadonlySet<string> = new Set([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'UNKNOWN',
]);

function normalizeSeverityLabel(raw: string | undefined): Severity {
  const upper = (raw ?? '').toUpperCase();
  return KNOWN_SEVERITIES.has(upper) ? (upper as Severity) : 'UNKNOWN';
}

/** Pick the highest CVSS v3 base score across whichever vendors Trivy
 * reported (nvd, redhat, ghsa, ...); falls back to the highest v2 score if
 * no vendor reported a v3 score. Returns undefined if Trivy reported no
 * CVSS data at all for this vulnerability. */
function extractCvssScore(cvss: Record<string, TrivyCvssVendorScore> | undefined): number | undefined {
  if (!cvss) return undefined;
  const vendorScores = Object.values(cvss);
  const v3Scores = vendorScores
    .map((v) => v.V3Score)
    .filter((n): n is number => typeof n === 'number' && Number.isFinite(n));
  if (v3Scores.length > 0) return Math.max(...v3Scores);

  const v2Scores = vendorScores
    .map((v) => v.V2Score)
    .filter((n): n is number => typeof n === 'number' && Number.isFinite(n));
  if (v2Scores.length > 0) return Math.max(...v2Scores);

  return undefined;
}

/** Parse a Trivy JSON report (already `JSON.parse`d) into VulnTriage's
 * normalized `ScannerFinding[]`. Each finding's `target` is the specific
 * Trivy `Result.Target` (e.g. `"alpine:3.18 (alpine 3.18.4)"` or a lockfile
 * path) rather than the report-level `ArtifactName`, since a single report
 * can cover multiple targets (OS packages + language-specific lockfiles)
 * that a user may want to assign different asset criticality. */
export function parseTrivyReport(report: TrivyReport): ScannerFinding[] {
  const findings: ScannerFinding[] = [];
  const fallbackTarget = report.ArtifactName ?? 'unknown-target';

  for (const result of report.Results ?? []) {
    const target = result.Target ?? fallbackTarget;
    for (const vuln of result.Vulnerabilities ?? []) {
      const cvssScore = extractCvssScore(vuln.CVSS);
      const finding: ScannerFinding = {
        id: vuln.VulnerabilityID,
        target,
        severity: normalizeSeverityLabel(vuln.Severity),
        sourceScanner: 'trivy',
        ...(vuln.PkgName !== undefined ? { packageName: vuln.PkgName } : {}),
        ...(vuln.InstalledVersion !== undefined ? { installedVersion: vuln.InstalledVersion } : {}),
        ...(vuln.FixedVersion !== undefined ? { fixedVersion: vuln.FixedVersion } : {}),
        ...(cvssScore !== undefined ? { cvssScore } : {}),
        ...(vuln.Title !== undefined ? { title: vuln.Title } : {}),
        ...(vuln.Description !== undefined ? { description: vuln.Description } : {}),
      };
      findings.push(finding);
    }
  }

  return findings;
}

/** Parse a raw JSON string of a Trivy report. Throws a descriptive error if
 * the input is not valid JSON or is obviously not a Trivy report. */
export function parseTrivyReportText(text: string): ScannerFinding[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`Failed to parse Trivy report as JSON: ${(err as Error).message}`);
  }
  if (typeof parsed !== 'object' || parsed === null || !('Results' in parsed)) {
    throw new Error(
      'Input does not look like a Trivy JSON report (missing top-level "Results" array). ' +
        'Generate one with `trivy image -f json -o report.json <image>`.',
    );
  }
  return parseTrivyReport(parsed as TrivyReport);
}
