import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseGrypeReport, parseGrypeReportText } from './grype.js';
import type { GrypeReport } from './grype.js';

const fixturePath = fileURLToPath(new URL('../../test/fixtures/grype-report.json', import.meta.url));

describe('parseGrypeReport', () => {
  it('normalizes vulnerabilities from a real Grype JSON report, one per match', async () => {
    const text = await readFile(fixturePath, 'utf8');
    const findings = parseGrypeReportText(text);

    expect(findings).toHaveLength(4);
    expect(findings.every((f) => f.sourceScanner === 'grype')).toBe(true);
    expect(findings.every((f) => f.target === 'legacy-app:2.1.0')).toBe(true);
  });

  it('extracts package name, version, CVSS score, and fix info', async () => {
    const text = await readFile(fixturePath, 'utf8');
    const findings = parseGrypeReportText(text);

    const openssl = findings.find((f) => f.id === 'CVE-2023-0157');
    expect(openssl?.packageName).toBe('openssl');
    expect(openssl?.installedVersion).toBe('1.1.1t-r0');
    expect(openssl?.fixedVersion).toBe('1.1.1u-r0');
    expect(openssl?.cvssScore).toBe(7.5);
    expect(openssl?.severity).toBe('HIGH');
  });

  it('leaves fixedVersion undefined when fix.state is not "fixed"', async () => {
    const text = await readFile(fixturePath, 'utf8');
    const findings = parseGrypeReportText(text);

    const bluekeep = findings.find((f) => f.id === 'CVE-2019-0708');
    expect(bluekeep?.fixedVersion).toBeUndefined();
  });

  it('maps Grype "Negligible" severity to UNKNOWN', async () => {
    const text = await readFile(fixturePath, 'utf8');
    const findings = parseGrypeReportText(text);

    const placeholder = findings.find((f) => f.id === 'CVE-9999-0002');
    expect(placeholder?.severity).toBe('UNKNOWN');
    expect(placeholder?.cvssScore).toBeUndefined();
  });

  it('prefers CVSS v3 entries over v2 when both are present', () => {
    const report: GrypeReport = {
      matches: [
        {
          vulnerability: {
            id: 'CVE-2000-0001',
            severity: 'High',
            cvss: [
              { version: '2.0', metrics: { baseScore: 5.0 } },
              { version: '3.1', metrics: { baseScore: 8.8 } },
            ],
          },
          artifact: { name: 'pkg', version: '1.0' },
        },
      ],
      source: { target: { userInput: 't' } },
    };
    const [finding] = parseGrypeReport(report);
    expect(finding?.cvssScore).toBe(8.8);
  });

  it('falls back to the artifact name as target when source is absent', () => {
    const report: GrypeReport = {
      matches: [{ vulnerability: { id: 'CVE-2000-0002', severity: 'Low' }, artifact: { name: 'lonely-pkg' } }],
    };
    const [finding] = parseGrypeReport(report);
    expect(finding?.target).toBe('lonely-pkg');
  });

  it('supports a bare-string source.target for older report variants', () => {
    const report: GrypeReport = {
      matches: [{ vulnerability: { id: 'CVE-2000-0003', severity: 'Low' } }],
      source: { target: '/path/to/dir' },
    };
    const [finding] = parseGrypeReport(report);
    expect(finding?.target).toBe('/path/to/dir');
  });

  it('returns an empty array for a report with no matches', () => {
    expect(parseGrypeReport({})).toEqual([]);
  });
});

describe('parseGrypeReportText error handling', () => {
  it('throws a descriptive error on invalid JSON', () => {
    expect(() => parseGrypeReportText('not json')).toThrow(/Failed to parse Grype report as JSON/);
  });

  it('throws a descriptive error when the JSON is not a Grype report', () => {
    expect(() => parseGrypeReportText('{"Results": []}')).toThrow(/does not look like a Grype JSON report/);
  });
});
