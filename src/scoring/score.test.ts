import { describe, expect, it } from 'vitest';
import type { KevEntry } from '../types.js';
import {
  ASSET_WEIGHT,
  EPSS_WEIGHT,
  KEV_WEIGHT,
  SEVERITY_WEIGHT,
  isKevListed,
  normalizeAssetCriticality,
  normalizeSeverity,
  scoreFinding,
} from './score.js';

function kevEntry(cveID: string): KevEntry {
  return {
    cveID,
    vendorProject: 'Acme',
    product: 'Widget',
    vulnerabilityName: 'Example vulnerability',
    dateAdded: '2024-01-01',
    shortDescription: 'Example',
    requiredAction: 'Apply updates',
    dueDate: '2024-02-01',
    knownRansomwareCampaignUse: 'Unknown',
  };
}

describe('normalizeSeverity', () => {
  it('prefers a numeric CVSS score over the severity bucket when present', () => {
    expect(normalizeSeverity({ severity: 'LOW', cvssScore: 9.8 })).toBeCloseTo(0.98);
  });

  it('falls back to the severity bucket when no CVSS score is present', () => {
    expect(normalizeSeverity({ severity: 'CRITICAL' })).toBeCloseTo(0.9);
    expect(normalizeSeverity({ severity: 'HIGH' })).toBeCloseTo(0.7);
    expect(normalizeSeverity({ severity: 'MEDIUM' })).toBeCloseTo(0.5);
    expect(normalizeSeverity({ severity: 'LOW' })).toBeCloseTo(0.3);
    expect(normalizeSeverity({ severity: 'UNKNOWN' })).toBeCloseTo(0.1);
  });

  it('clamps out-of-range CVSS scores defensively', () => {
    expect(normalizeSeverity({ severity: 'LOW', cvssScore: 55 })).toBe(1);
    expect(normalizeSeverity({ severity: 'LOW', cvssScore: -3 })).toBe(0);
  });
});

describe('normalizeAssetCriticality', () => {
  it('maps each tag to its fixed score', () => {
    expect(normalizeAssetCriticality('critical')).toBe(1.0);
    expect(normalizeAssetCriticality('high')).toBe(0.75);
    expect(normalizeAssetCriticality('medium')).toBe(0.5);
    expect(normalizeAssetCriticality('low')).toBe(0.25);
  });

  it('defaults to the medium score when no tag is available', () => {
    expect(normalizeAssetCriticality(undefined)).toBe(0.5);
  });
});

describe('isKevListed', () => {
  it('returns true when the CVE id is present in the KEV index', () => {
    const kevByCve = new Map([['CVE-2021-44228', kevEntry('CVE-2021-44228')]]);
    expect(isKevListed('CVE-2021-44228', kevByCve)).toBe(true);
  });

  it('returns false when the CVE id is absent from the KEV index', () => {
    const kevByCve = new Map([['CVE-2021-44228', kevEntry('CVE-2021-44228')]]);
    expect(isKevListed('CVE-2020-1472', kevByCve)).toBe(false);
  });

  it('is case-insensitive on the CVE id', () => {
    const kevByCve = new Map([['CVE-2021-44228', kevEntry('CVE-2021-44228')]]);
    expect(isKevListed('cve-2021-44228', kevByCve)).toBe(true);
  });
});

describe('scoreFinding: weights and totals', () => {
  it('sums the four weighted components into `total`', () => {
    const breakdown = scoreFinding({
      finding: { severity: 'HIGH' },
      epssScore: 0.4,
      kevListed: false,
      assetCriticality: 'high',
    });
    // 0 (no KEV) + 25*0.4 + 15*0.7 + 15*0.75 = 0 + 10 + 10.5 + 11.25 = 31.75
    expect(breakdown.kevComponent).toBeCloseTo(0);
    expect(breakdown.epssComponent).toBeCloseTo(10);
    expect(breakdown.severityComponent).toBeCloseTo(10.5);
    expect(breakdown.assetComponent).toBeCloseTo(11.25);
    expect(breakdown.total).toBeCloseTo(31.75);
  });

  it('the four weights sum to exactly 100, so a maximal finding scores exactly 100', () => {
    expect(KEV_WEIGHT + EPSS_WEIGHT + SEVERITY_WEIGHT + ASSET_WEIGHT).toBe(100);
    const breakdown = scoreFinding({
      finding: { severity: 'CRITICAL', cvssScore: 10 },
      epssScore: 1,
      kevListed: true,
      assetCriticality: 'critical',
    });
    expect(breakdown.total).toBe(100);
  });

  it('a finding with none of the four signals scores exactly 0', () => {
    const breakdown = scoreFinding({
      finding: { severity: 'UNKNOWN', cvssScore: 0 },
      epssScore: 0,
      kevListed: false,
      assetCriticality: 'low',
    });
    // severity contributes 0 (cvssScore 0/10), asset "low" contributes 15*0.25 = 3.75
    expect(breakdown.total).toBeCloseTo(3.75);
  });

  it('never exceeds 100 even with a defensively out-of-range EPSS input', () => {
    const breakdown = scoreFinding({
      finding: { severity: 'CRITICAL', cvssScore: 10 },
      epssScore: 5, // malformed input: EPSS is defined on [0,1]
      kevListed: true,
      assetCriticality: 'critical',
    });
    expect(breakdown.total).toBeLessThanOrEqual(100);
  });
});

describe('scoreFinding: the core value proposition', () => {
  it('a KEV-listed MEDIUM-severity finding outranks a non-KEV CRITICAL finding, all else equal', () => {
    // Same asset criticality, same (low, conservative) EPSS score for both -
    // isolating the comparison to "does KEV membership alone flip the
    // ranking versus a plain CVSS/severity signal", which is the entire
    // reason VulnTriage exists instead of just sorting by CVSS.
    const kevMedium = scoreFinding({
      finding: { severity: 'MEDIUM' },
      epssScore: 0.1,
      kevListed: true,
      assetCriticality: 'medium',
    });
    const nonKevCritical = scoreFinding({
      finding: { severity: 'CRITICAL', cvssScore: 9.8 },
      epssScore: 0.1,
      kevListed: false,
      assetCriticality: 'medium',
    });

    expect(kevMedium.total).toBeGreaterThan(nonKevCritical.total);
    // Concretely: 45 + 2.5 + 7.5 + 7.5 = 62.5 vs 0 + 2.5 + 14.7 + 7.5 = 24.7
    expect(kevMedium.total).toBeCloseTo(62.5);
    expect(nonKevCritical.total).toBeCloseTo(24.7);
  });

  it('still holds even when the non-KEV CRITICAL finding has a much higher EPSS score than the KEV finding', () => {
    const kevMedium = scoreFinding({
      finding: { severity: 'MEDIUM' },
      epssScore: 0.05,
      kevListed: true,
      assetCriticality: 'medium',
    });
    const nonKevCriticalHighEpss = scoreFinding({
      finding: { severity: 'CRITICAL', cvssScore: 9.8 },
      epssScore: 0.6,
      kevListed: false,
      assetCriticality: 'medium',
    });

    expect(kevMedium.total).toBeGreaterThan(nonKevCriticalHighEpss.total);
  });

  it('still holds even when the non-KEV CRITICAL finding is on a more critical asset', () => {
    const kevMediumLowAsset = scoreFinding({
      finding: { severity: 'MEDIUM' },
      epssScore: 0.1,
      kevListed: true,
      assetCriticality: 'low',
    });
    const nonKevCriticalHighAsset = scoreFinding({
      finding: { severity: 'CRITICAL', cvssScore: 10 },
      epssScore: 0.1,
      kevListed: false,
      assetCriticality: 'critical',
    });

    // 45 + 2.5 + 7.5 + 3.75 = 58.75 vs 0 + 2.5 + 15 + 15 = 32.5
    expect(kevMediumLowAsset.total).toBeGreaterThan(nonKevCriticalHighAsset.total);
  });

  it('exposes kevListed and epssScore verbatim in the breakdown for CLI explanation output', () => {
    const breakdown = scoreFinding({
      finding: { severity: 'LOW' },
      epssScore: 0.234,
      kevListed: true,
      assetCriticality: 'low',
    });
    expect(breakdown.kevListed).toBe(true);
    expect(breakdown.epssScore).toBeCloseTo(0.234);
    expect(breakdown.weights).toEqual({
      kev: KEV_WEIGHT,
      epss: EPSS_WEIGHT,
      severity: SEVERITY_WEIGHT,
      asset: ASSET_WEIGHT,
    });
  });
});
