import { readFile } from 'node:fs/promises';
import { Command } from 'commander';
import type { ScannerName } from '../types.js';
import { detectScannerFormat, parseScannerReport } from '../parsers/index.js';
import { HttpEpssClient, FileEpssClient, buildEpssIndex } from '../sources/epss.js';
import { HttpKevClient, FileKevClient, buildKevIndex } from '../sources/kev.js';
import { validateAssetCriticalityConfig } from '../merge/assets.js';
import { mergeAndScore, rankFindings } from '../merge/merge.js';
import { formatJson, formatText } from './format.js';

async function readPackageVersion(): Promise<string> {
  try {
    const url = new URL('../../package.json', import.meta.url);
    const text = await readFile(url, 'utf8');
    const pkg = JSON.parse(text) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export interface CliIo {
  readonly stdout: (line: string) => void;
  readonly stderr: (line: string) => void;
}

const defaultIo: CliIo = {
  stdout: (line) => process.stdout.write(line),
  stderr: (line) => process.stderr.write(line),
};

/** Build the commander program. Exposed separately from `run` so tests can
 * introspect option parsing without executing the full pipeline. */
export function buildProgram(version: string): Command {
  const program = new Command();
  program
    .name('vulntriage')
    .description(
      'Merge scanner findings (Trivy/Grype) with real EPSS exploit-probability scores, ' +
        'the real CISA KEV catalog, and your asset-criticality tags into one deterministic, ' +
        'explainable ranked list.',
    )
    .version(version)
    .requiredOption('-i, --input <path>', 'path to a scanner report (Trivy or Grype JSON)')
    .option('-f, --format <format>', 'scanner format: trivy, grype, or auto', 'auto')
    .option('-a, --assets <path>', 'path to an asset-criticality JSON config')
    .option('--epss-file <path>', 'load EPSS scores from a local CSV snapshot instead of the live API')
    .option('--kev-file <path>', 'load the KEV catalog from a local JSON snapshot instead of the live feed')
    .option('-o, --output <mode>', 'output mode: text or json', 'text')
    .option('--top <n>', 'only show the top N findings', (v) => Number.parseInt(v, 10));
  return program;
}

/** Run the VulnTriage CLI end-to-end. `argv` is the *user-supplied*
 * argument list only - the same slice `bin/vulntriage.js` passes via
 * `process.argv.slice(2)`, i.e. it must NOT include a leading node
 * executable path or script path. Writes to the given IO sinks (real
 * stdout/stderr by default; tests may inject capturing sinks). Returns a
 * process exit code. */
export async function run(argv: readonly string[], io: CliIo = defaultIo): Promise<number> {
  const version = await readPackageVersion();
  const program = buildProgram(version);

  // By default commander writes help/errors straight to the real
  // process streams and calls process.exit(), which would both bypass the
  // injected `io` sinks and kill the test runner. Route output through
  // `io` and convert exit attempts into a thrown CommanderError instead.
  program.configureOutput({
    writeOut: (str) => io.stdout(str),
    writeErr: (str) => io.stderr(str),
  });
  program.exitOverride();

  try {
    program.parse(argv, { from: 'user' });
  } catch (err) {
    const commanderErr = err as { code?: string; exitCode?: number; message?: string };
    if (typeof commanderErr.code === 'string' && commanderErr.code.startsWith('commander.')) {
      return commanderErr.exitCode ?? 0;
    }
    io.stderr(`${(err as Error).message}\n`);
    return 1;
  }

  const opts = program.opts<{
    input: string;
    format: string;
    assets?: string;
    epssFile?: string;
    kevFile?: string;
    output: string;
    top?: number;
  }>();

  if (opts.output !== 'text' && opts.output !== 'json') {
    io.stderr(`Invalid --output "${opts.output}": expected "text" or "json"\n`);
    return 1;
  }

  try {
    const reportText = await readFile(opts.input, 'utf8');

    let format: ScannerName;
    if (opts.format === 'auto') {
      const detected = detectScannerFormat(reportText);
      if (!detected) {
        io.stderr('Could not auto-detect scanner format. Pass --format trivy|grype explicitly.\n');
        return 1;
      }
      format = detected;
    } else if (opts.format === 'trivy' || opts.format === 'grype') {
      format = opts.format;
    } else {
      io.stderr(`Invalid --format "${opts.format}": expected "trivy", "grype", or "auto"\n`);
      return 1;
    }

    const findings = parseScannerReport(format, reportText);
    const cveIds = [...new Set(findings.map((f) => f.id))];

    const epssClient = opts.epssFile ? new FileEpssClient(opts.epssFile) : new HttpEpssClient();
    const kevClient = opts.kevFile ? new FileKevClient(opts.kevFile) : new HttpKevClient();

    const [epssEntries, kevEntries] = await Promise.all([
      epssClient.fetchScores(cveIds),
      kevClient.fetchCatalog(),
    ]);

    const assetConfig = opts.assets
      ? validateAssetCriticalityConfig(JSON.parse(await readFile(opts.assets, 'utf8')))
      : undefined;

    const scored = mergeAndScore({
      findings,
      epssIndex: buildEpssIndex(epssEntries),
      kevIndex: buildKevIndex(kevEntries),
      ...(assetConfig !== undefined ? { assetConfig } : {}),
    });

    let ranked = rankFindings(scored);
    if (typeof opts.top === 'number' && Number.isFinite(opts.top) && opts.top >= 0) {
      ranked = ranked.slice(0, opts.top);
    }

    io.stdout(opts.output === 'json' ? `${formatJson(ranked)}\n` : formatText(ranked));
    return 0;
  } catch (err) {
    io.stderr(`vulntriage: ${(err as Error).message}\n`);
    return 1;
  }
}
