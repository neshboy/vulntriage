import { describe, expect, it } from 'vitest';
import { detectScannerFormat, parseScannerReport } from './index.js';

describe('detectScannerFormat', () => {
  it('detects a Trivy report by its SchemaVersion + Results shape', () => {
    expect(detectScannerFormat('{"SchemaVersion": 2, "Results": []}')).toBe('trivy');
  });

  it('detects a Grype report by its matches shape', () => {
    expect(detectScannerFormat('{"matches": []}')).toBe('grype');
  });

  it('returns undefined for unrecognized JSON', () => {
    expect(detectScannerFormat('{"foo": "bar"}')).toBeUndefined();
  });

  it('returns undefined for invalid JSON', () => {
    expect(detectScannerFormat('not json')).toBeUndefined();
  });
});

describe('parseScannerReport', () => {
  it('dispatches to the Trivy parser', () => {
    const findings = parseScannerReport(
      'trivy',
      JSON.stringify({ Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-2000-0001', Severity: 'LOW' }] }] }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.sourceScanner).toBe('trivy');
  });

  it('dispatches to the Grype parser', () => {
    const findings = parseScannerReport(
      'grype',
      JSON.stringify({ matches: [{ vulnerability: { id: 'CVE-2000-0001', severity: 'Low' }, artifact: { name: 'p' } }] }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.sourceScanner).toBe('grype');
  });
});
