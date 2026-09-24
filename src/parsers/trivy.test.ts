import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseTrivyReport, parseTrivyReportText } from './trivy.js';
import type { TrivyReport } from './trivy.js';

const fixturePath = fileURLToPath(new URL('../../test/fixtures/trivy-report.json', import.meta.url));

describe('parseTrivyReport', () => {
  it('normalizes vulnerabilities from a real Trivy JSON report, one per Vulnerability entry', async () => {
    const text = await readFile(fixturePath, 'utf8');
    const findings = parseTrivyReportText(text);

    expect(findings).toHaveLength(5);
    const ids = findings.map((f) => f.id);
    expect(ids).toEqual(
      expect.arrayContaining(['CVE-2020-1472', 'CVE-2023-38545', 'CVE-2023-0048', 'CVE-9999-0001', 'CVE-2021-44228']),
    );
    expect(findings.every((f) => f.sourceScanner === 'trivy')).toBe(true);
  });

  it('uses the per-Result Target, not the report-level ArtifactName, as the finding target', async () => {
    const text = await readFile(fixturePath, 'utf8');
    const findings = parseTrivyReportText(text);

    const log4j = findings.find((f) => f.id === 'CVE-2021-44228');
    expect(log4j?.target).toBe('sample-app:1.0.0 (java-jar)');

    const zerologon = findings.find((f) => f.id === 'CVE-2020-1472');
    expect(zerologon?.target).toBe('sample-app:1.0.0 (alpine 3.19.1)');
  });

  it('extracts the highest reported CVSS v3 score across vendors', async () => {
    const text = await readFile(fixturePath, 'utf8');
    const findings = parseTrivyReportText(text);

    const curl = findings.find((f) => f.id === 'CVE-2023-38545');
    expect(curl?.cvssScore).toBe(9.8);
    expect(curl?.severity).toBe('CRITICAL');
    expect(curl?.packageName).toBe('curl');
    expect(curl?.installedVersion).toBe('8.3.0-r0');
    expect(curl?.fixedVersion).toBe('8.4.0-r0');
  });

  it('leaves cvssScore undefined when Trivy reported no CVSS data', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 't',
          Vulnerabilities: [{ VulnerabilityID: 'CVE-2000-0001', Severity: 'LOW' }],
        },
      ],
    };
    const [finding] = parseTrivyReport(report);
    expect(finding?.cvssScore).toBeUndefined();
  });

  it('normalizes unrecognized severity strings to UNKNOWN', () => {
    const report: TrivyReport = {
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-2000-0002', Severity: 'WEIRD' }] }],
    };
    const [finding] = parseTrivyReport(report);
    expect(finding?.severity).toBe('UNKNOWN');
  });

  it('falls back to ArtifactName when a Result has no Target', () => {
    const report: TrivyReport = {
      ArtifactName: 'fallback-target',
      Results: [{ Vulnerabilities: [{ VulnerabilityID: 'CVE-2000-0003', Severity: 'HIGH' }] }],
    };
    const [finding] = parseTrivyReport(report);
    expect(finding?.target).toBe('fallback-target');
  });

  it('returns an empty array for a report with no Results', () => {
    expect(parseTrivyReport({})).toEqual([]);
  });
});

describe('parseTrivyReportText error handling', () => {
  it('throws a descriptive error on invalid JSON', () => {
    expect(() => parseTrivyReportText('not json')).toThrow(/Failed to parse Trivy report as JSON/);
  });

  it('throws a descriptive error when the JSON is not a Trivy report', () => {
    expect(() => parseTrivyReportText('{"matches": []}')).toThrow(/does not look like a Trivy JSON report/);
  });
});
