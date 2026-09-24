import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { run } from './index.js';
import type { JsonOutput } from './format.js';

const fixturePath = (name: string) => fileURLToPath(new URL(`../../test/fixtures/${name}`, import.meta.url));

function captureIo() {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    io: {
      stdout: (line: string) => stdout.push(line),
      stderr: (line: string) => stderr.push(line),
    },
    stdout: () => stdout.join(''),
    stderr: () => stderr.join(''),
  };
}

describe('vulntriage CLI: end-to-end against real trimmed fixtures', () => {
  it('triages a Trivy report and prints JSON with a real KEV finding outranking a real non-KEV CRITICAL finding', async () => {
    const cap = captureIo();
    const code = await run(
      [
        '--input',
        fixturePath('trivy-report.json'),
        '--format',
        'trivy',
        '--epss-file',
        fixturePath('epss-snapshot.csv'),
        '--kev-file',
        fixturePath('kev-snapshot.json'),
        '--assets',
        fixturePath('assets.json'),
        '--output',
        'json',
      ],
      cap.io,
    );

    expect(code).toBe(0);
    expect(cap.stderr()).toBe('');

    const parsed = JSON.parse(cap.stdout()) as JsonOutput;
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.weights).toEqual({ kev: 45, epss: 25, severity: 15, asset: 15 });
    expect(parsed.findings).toHaveLength(5);

    const ids = parsed.findings.map((f) => f.id);
    expect(ids.indexOf('CVE-2020-1472')).toBeLessThan(ids.indexOf('CVE-2023-38545'));

    const zerologon = parsed.findings.find((f) => f.id === 'CVE-2020-1472');
    expect(zerologon?.score.kevListed).toBe(true);
  });

  it('auto-detects the Grype format when --format is omitted', async () => {
    const cap = captureIo();
    const code = await run(
      [
        '--input',
        fixturePath('grype-report.json'),
        '--epss-file',
        fixturePath('epss-snapshot.csv'),
        '--kev-file',
        fixturePath('kev-snapshot.json'),
        '--output',
        'json',
      ],
      cap.io,
    );

    expect(code).toBe(0);
    const parsed = JSON.parse(cap.stdout()) as JsonOutput;
    expect(parsed.findings.every((f) => f.sourceScanner === 'grype')).toBe(true);
    expect(parsed.findings.map((f) => f.id)).toContain('CVE-2019-0708');
  });

  it('prints a human-readable, self-explaining plain-text report by default', async () => {
    const cap = captureIo();
    const code = await run(
      [
        '--input',
        fixturePath('trivy-report.json'),
        '--format',
        'trivy',
        '--epss-file',
        fixturePath('epss-snapshot.csv'),
        '--kev-file',
        fixturePath('kev-snapshot.json'),
      ],
      cap.io,
    );

    expect(code).toBe(0);
    const text = cap.stdout();
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('KEV=YES');
    expect(text).toMatch(/score=\d+\.\d{2}/);
  });

  it('honors --top to limit the number of findings shown', async () => {
    const cap = captureIo();
    const code = await run(
      [
        '--input',
        fixturePath('trivy-report.json'),
        '--format',
        'trivy',
        '--epss-file',
        fixturePath('epss-snapshot.csv'),
        '--kev-file',
        fixturePath('kev-snapshot.json'),
        '--output',
        'json',
        '--top',
        '2',
      ],
      cap.io,
    );

    expect(code).toBe(0);
    const parsed = JSON.parse(cap.stdout()) as JsonOutput;
    expect(parsed.findings).toHaveLength(2);
  });

  it('exits non-zero with a message on stderr when the input file does not exist', async () => {
    const cap = captureIo();
    const code = await run(['--input', fixturePath('does-not-exist.json')], cap.io);

    expect(code).toBe(1);
    expect(cap.stderr()).toContain('vulntriage:');
  });

  it('exits non-zero when a required option is missing', async () => {
    const cap = captureIo();
    const code = await run([], cap.io);
    expect(code).not.toBe(0);
  });

  it('rejects an invalid --output value', async () => {
    const cap = captureIo();
    const code = await run(
      ['--input', fixturePath('trivy-report.json'), '--output', 'xml'],
      cap.io,
    );
    expect(code).toBe(1);
    expect(cap.stderr()).toContain('Invalid --output');
  });

  it('rejects an invalid --format value', async () => {
    const cap = captureIo();
    const code = await run(
      ['--input', fixturePath('trivy-report.json'), '--format', 'nessus'],
      cap.io,
    );
    expect(code).toBe(1);
    expect(cap.stderr()).toContain('Invalid --format');
  });

  it('supports --help without crashing and without hitting a real network dependency', async () => {
    const cap = captureIo();
    const code = await run(['--help'], cap.io);
    expect(code).toBe(0);
    expect(cap.stdout()).toContain('Usage:');
  });
});
