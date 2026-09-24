import type { ScoredFinding } from '../types.js';
import { KEV_WEIGHT, EPSS_WEIGHT, SEVERITY_WEIGHT, ASSET_WEIGHT } from '../scoring/score.js';

/** Render a ranked finding list as human-readable plain text, one block per
 * finding, each showing the exact scoring breakdown so the ranking is
 * self-explaining without cross-referencing the README. */
export function formatText(ranked: readonly ScoredFinding[]): string {
  if (ranked.length === 0) {
    return 'No findings.\n';
  }

  const lines: string[] = [];
  lines.push(
    `VulnTriage ranked ${ranked.length} finding${ranked.length === 1 ? '' : 's'} ` +
      `(${ranked.filter((f) => f.score.kevListed).length} on the CISA KEV catalog)`,
  );
  lines.push('');

  ranked.forEach((finding, index) => {
    const rank = index + 1;
    const pkg =
      finding.packageName !== undefined
        ? ` ${finding.packageName}${finding.installedVersion !== undefined ? `@${finding.installedVersion}` : ''}${
            finding.fixedVersion !== undefined ? ` (fixed in ${finding.fixedVersion})` : ''
          }`
        : '';

    lines.push(`#${rank}  ${finding.id}  score=${finding.score.total.toFixed(2)}  target=${finding.target}${pkg}`);
    lines.push(
      `    KEV=${finding.score.kevListed ? 'YES' : 'no'} (+${finding.score.kevComponent.toFixed(2)}/${KEV_WEIGHT}) ` +
        `EPSS=${finding.score.epssScore.toFixed(4)} (+${finding.score.epssComponent.toFixed(2)}/${EPSS_WEIGHT}) ` +
        `severity=${finding.score.severity} (+${finding.score.severityComponent.toFixed(2)}/${SEVERITY_WEIGHT}) ` +
        `asset=${finding.score.assetCriticality} (+${finding.score.assetComponent.toFixed(2)}/${ASSET_WEIGHT})`,
    );
    if (finding.title !== undefined) {
      lines.push(`    ${finding.title}`);
    }
    lines.push('');
  });

  return lines.join('\n');
}

export interface JsonOutput {
  readonly schemaVersion: 1;
  readonly weights: {
    readonly kev: number;
    readonly epss: number;
    readonly severity: number;
    readonly asset: number;
  };
  readonly findings: readonly ScoredFinding[];
}

/** Render a ranked finding list as structured JSON. Deliberately excludes
 * anything time-varying (no generated-at timestamp) so identical inputs
 * always produce byte-identical output. */
export function formatJson(ranked: readonly ScoredFinding[]): string {
  const output: JsonOutput = {
    schemaVersion: 1,
    weights: { kev: KEV_WEIGHT, epss: EPSS_WEIGHT, severity: SEVERITY_WEIGHT, asset: ASSET_WEIGHT },
    findings: ranked,
  };
  return JSON.stringify(output, null, 2);
}
