import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { mergeAndScore, rankFindings } from './merge.js';
import { validateAssetCriticalityConfig } from './assets.js';
import { parseTrivyReportText } from '../parsers/trivy.js';
import { parseGrypeReportText } from '../parsers/grype.js';
import { FileEpssClient, buildEpssIndex } from '../sources/epss.js';
import { FileKevClient, buildKevIndex } from '../sources/kev.js';

const fixtureUrl = (name: string) => fileURLToPath(new URL(`../../test/fixtures/${name}`, import.meta.url));

/** Loads the real trimmed EPSS/KEV snapshots plus both sample scanner
 * reports and the sample asset-criticality config, exactly as the CLI
 * would, but in-process. This is the full merge+scoring pipeline exercised
 * against real (if trimmed) upstream data formats end-to-end. */
async function loadFixtures() {
  const [trivyText, grypeText, assetsText] = await Promise.all([
    readFile(fixtureUrl('trivy-report.json'), 'utf8'),
    readFile(fixtureUrl('grype-report.json'), 'utf8'),
    readFile(fixtureUrl('assets.json'), 'utf8'),
  ]);

  const findings = [...parseTrivyReportText(trivyText), ...parseGrypeReportText(grypeText)];
  const cveIds = findings.map((f) => f.id);

  const epssEntries = await new FileEpssClient(fixtureUrl('epss-snapshot.csv')).fetchScores(cveIds);
  const kevEntries = await new FileKevClient(fixtureUrl('kev-snapshot.json')).fetchCatalog();
  const assetConfig = validateAssetCriticalityConfig(JSON.parse(assetsText));

  return {
    findings,
    epssIndex: buildEpssIndex(epssEntries),
    kevIndex: buildKevIndex(kevEntries),
    assetConfig,
  };
}

describe('mergeAndScore + rankFindings: full pipeline against real trimmed data', () => {
  it('ranks a KEV-listed finding above a same-asset, non-KEV CRITICAL finding, even when the scanner labeled the KEV finding lower severity', async () => {
    const { findings, epssIndex, kevIndex, assetConfig } = await loadFixtures();
    const ranked = rankFindings(mergeAndScore({ findings, epssIndex, kevIndex, assetConfig }));

    const zerologon = ranked.find((f) => f.id === 'CVE-2020-1472'); // KEV-listed, fixture severity MEDIUM
    const curl = ranked.find((f) => f.id === 'CVE-2023-38545'); // not KEV, real CRITICAL severity

    expect(zerologon).toBeDefined();
    expect(curl).toBeDefined();
    // Both findings are on the same target (sample-app:1.0.0*), so
    // asset criticality is identical for both - isolating the comparison
    // to KEV membership as the deciding factor, exactly as in
    // src/scoring/score.test.ts, but now proven through the real
    // parse -> merge -> score pipeline instead of calling scoreFinding
    // directly.
    expect(zerologon!.score.assetCriticality).toBe(curl!.score.assetCriticality);
    expect(zerologon!.score.kevListed).toBe(true);
    expect(curl!.score.kevListed).toBe(false);
    expect(zerologon!.score.total).toBeGreaterThan(curl!.score.total);

    const rankOf = (id: string) => ranked.findIndex((f) => f.id === id);
    expect(rankOf('CVE-2020-1472')).toBeLessThan(rankOf('CVE-2023-38545'));
  });

  it('correctly looks up real EPSS scores and real KEV membership by CVE id across both scanner formats', async () => {
    const { findings, epssIndex, kevIndex, assetConfig } = await loadFixtures();
    const scored = mergeAndScore({ findings, epssIndex, kevIndex, assetConfig });

    const log4shell = scored.find((f) => f.id === 'CVE-2021-44228');
    expect(log4shell?.score.kevListed).toBe(true);
    expect(log4shell?.score.epssScore).toBeCloseTo(0.99999);

    const bluekeep = scored.find((f) => f.id === 'CVE-2019-0708');
    expect(bluekeep?.score.kevListed).toBe(true);
    expect(bluekeep?.score.epssScore).toBeCloseTo(0.99999);
    expect(bluekeep?.sourceScanner).toBe('grype');
  });

  it('defaults EPSS to 0 and KEV to false for CVEs with no upstream record, rather than erroring', async () => {
    const { findings, epssIndex, kevIndex, assetConfig } = await loadFixtures();
    const scored = mergeAndScore({ findings, epssIndex, kevIndex, assetConfig });

    const noData = scored.find((f) => f.id === 'CVE-9999-0001');
    expect(noData?.score.epssScore).toBe(0);
    expect(noData?.score.kevListed).toBe(false);
  });

  it('applies asset-criticality rules by target, matching glob patterns from the config', async () => {
    const { findings, epssIndex, kevIndex, assetConfig } = await loadFixtures();
    const scored = mergeAndScore({ findings, epssIndex, kevIndex, assetConfig });

    const onSampleApp = scored.find((f) => f.target.startsWith('sample-app:1.0.0'));
    const onLegacyApp = scored.find((f) => f.target === 'legacy-app:2.1.0');
    expect(onSampleApp?.score.assetCriticality).toBe('critical');
    expect(onLegacyApp?.score.assetCriticality).toBe('low');
  });

  it('defaults asset criticality to "medium" when no asset config is supplied at all', async () => {
    const { findings, epssIndex, kevIndex } = await loadFixtures();
    const scored = mergeAndScore({ findings, epssIndex, kevIndex });
    expect(scored.every((f) => f.score.assetCriticality === 'medium')).toBe(true);
  });

  it('produces a fully deterministic, stably-sorted ranking independent of input order', async () => {
    const { findings, epssIndex, kevIndex, assetConfig } = await loadFixtures();
    const rankedA = rankFindings(mergeAndScore({ findings, epssIndex, kevIndex, assetConfig }));
    const rankedB = rankFindings(mergeAndScore({ findings: [...findings].reverse(), epssIndex, kevIndex, assetConfig }));

    expect(rankedA.map((f) => f.id)).toEqual(rankedB.map((f) => f.id));
    // Strictly descending total score (ties allowed to be equal, never ascending).
    for (let i = 1; i < rankedA.length; i++) {
      expect(rankedA[i]!.score.total).toBeLessThanOrEqual(rankedA[i - 1]!.score.total);
    }
  });
});
