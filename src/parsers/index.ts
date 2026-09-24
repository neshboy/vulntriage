import type { ScannerFinding, ScannerName } from '../types.js';
import { parseTrivyReportText } from './trivy.js';
import { parseGrypeReportText } from './grype.js';

export { parseTrivyReport, parseTrivyReportText } from './trivy.js';
export type { TrivyReport } from './trivy.js';
export { parseGrypeReport, parseGrypeReportText } from './grype.js';
export type { GrypeReport } from './grype.js';

/** Parse raw scanner report text into normalized findings, dispatching on
 * the declared format. */
export function parseScannerReport(format: ScannerName, text: string): ScannerFinding[] {
  switch (format) {
    case 'trivy':
      return parseTrivyReportText(text);
    case 'grype':
      return parseGrypeReportText(text);
  }
}

/** Best-effort auto-detection of scanner format from raw report text, used
 * by the CLI when `--format` is not given. Returns undefined if neither
 * known top-level shape is recognized. */
export function detectScannerFormat(text: string): ScannerName | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;
  if ('Results' in parsed && 'SchemaVersion' in parsed) return 'trivy';
  if ('matches' in parsed) return 'grype';
  return undefined;
}
