# VulnTriage

**A self-hosted correlation layer that turns raw vulnerability-scanner output into one deterministic, explainable, ranked "fix this first" list** - by merging it with the real EPSS exploit-probability score, the real CISA Known Exploited Vulnerabilities (KEV) catalog, and your own asset-criticality tags.

No ML. No LLM. No black box. Every score is a plain arithmetic sum of four documented, weighted inputs, and the CLI prints the actual numbers behind every rank.

## The problem

Running `trivy` or `grype` against a container image routinely produces hundreds of findings. Two things go wrong next:

1. **Scanner output alone doesn't tell you what to fix first.** A JSON dump of 200 CVEs sorted by ID, or by scan order, gives you no prioritization signal at all - someone has to manually triage it, every time, for every image, forever.
2. **CVSS severity alone is a bad prioritization signal.** CVSS measures theoretical impact *if* a vulnerability is exploited - it says nothing about whether anyone is actually exploiting it. In practice, a huge fraction of "CRITICAL" findings in any given scan are years-old library CVEs nobody has ever weaponized, while some of the most dangerous findings in the world (Log4Shell, EternalBlue, BlueKeep, ProxyLogon) have, at various points, carried only a MEDIUM or HIGH rating in some vendor's advisory. Sorting purely by CVSS buries "this is being actively exploited in the wild right now" findings under a pile of theoretical-but-inert criticals.

VulnTriage exists to fix exactly that: it combines the scanner's own severity signal with two *real, independently published* exploitation signals (EPSS and CISA KEV) and your own knowledge of which assets actually matter, into one number per finding, computed by a formula you can read, audit, and reproduce by hand.

## Quick start

```bash
git clone https://github.com/neshboy/vulntriage.git
cd vulntriage
npm install
npm run build

# Triage a real Trivy report, using the real live EPSS API + live CISA KEV feed
node bin/vulntriage.js --input trivy-report.json --format trivy

# Or install it as a global/linked command
npm link
vulntriage --input trivy-report.json --format trivy --output json
```

Generate a real Trivy/Grype report to feed it:

```bash
trivy image -f json -o trivy-report.json alpine:3.18
# or
grype alpine:3.18 -o json > grype-report.json
```

### Offline / air-gapped use

Pass local snapshot files instead of hitting the live EPSS API / CISA KEV feed:

```bash
vulntriage --input trivy-report.json --format trivy \
  --epss-file epss_scores-current.csv \
  --kev-file known_exploited_vulnerabilities.json
```

`--epss-file` expects the real EPSS bulk-CSV format published at
`https://epss.cyentia.com/epss_scores-current.csv.gz` (gunzip it first).
`--kev-file` expects the real JSON published at
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
This is also exactly how the test suite runs, hermetically, offline, against
small trimmed-but-real snapshots of both files (see `test/fixtures/README.md`).

## CLI reference

```
vulntriage --input <path> [options]

Required:
  -i, --input <path>       scanner report (Trivy or Grype JSON)

Options:
  -f, --format <format>    trivy | grype | auto        (default: auto)
  -a, --assets <path>      asset-criticality JSON config
      --epss-file <path>   local EPSS CSV snapshot instead of the live API
      --kev-file <path>    local KEV JSON snapshot instead of the live feed
  -o, --output <mode>      text | json                 (default: text)
      --top <n>            only show the top N findings
  -V, --version
  -h, --help
```

### Asset-criticality config

A JSON file mapping scan targets (image names, paths - whatever your
scanner reports as `Target`/`source.target.userInput`) to a business-
criticality tag, with glob (`*`) support and a default:

```json
{
  "defaultCriticality": "medium",
  "assets": [
    { "match": "payments-api*", "criticality": "critical" },
    { "match": "internal-tools*", "criticality": "low" }
  ]
}
```

Rules are evaluated top-to-bottom; the first match wins. Targets matching no
rule fall back to `defaultCriticality`. If `--assets` is omitted entirely,
every finding is treated as `medium`.

## The scoring formula

Every finding gets exactly one score, in `[0, 100]`, computed as:

```
total = 45 * kevComponent
      + 25 * epssComponent
      + 15 * severityComponent
      + 15 * assetComponent
```

The four weights are constants (`src/scoring/score.ts`) that sum to exactly
100, so `total` always lands in `[0, 100]`. Each component is itself
normalized to `[0, 1]`:

| Component | Weight | How it's computed |
|---|---|---|
| **KEV** | 45 | `1` if the CVE is on the real CISA KEV catalog right now, else `0`. Binary, and deliberately the single heaviest-weighted signal. |
| **EPSS** | 25 | The real EPSS probability (0-1) that this CVE will be exploited in the next 30 days, straight from FIRST.org. `0` if no EPSS record exists for the CVE. |
| **Severity** | 15 | `cvssScore / 10` if the scanner reported a numeric CVSS base score, else a fixed mapping from the severity bucket: CRITICAL=0.9, HIGH=0.7, MEDIUM=0.5, LOW=0.3, UNKNOWN=0.1. |
| **Asset criticality** | 15 | Your tag for the affected target: critical=1.0, high=0.75, medium=0.5, low=0.25 (medium if untagged). |

**Why KEV gets 45/100 on its own:** a CVE on the KEV catalog is not a
theoretical risk - CISA put it there because it has *confirmed evidence* of
active, in-the-wild exploitation. That single fact is worth almost half the
maximum possible score, before severity or asset criticality are even
considered, which is exactly what makes VulnTriage different from "sort by
CVSS descending."

### Worked example: the actual value proposition

A KEV-listed finding that a scanner rates only MEDIUM severity, versus a
non-KEV finding rated CRITICAL, same asset, same (deliberately low, so as
not to stack the deck) EPSS score of `0.1` for both:

```
KEV-listed MEDIUM:      45*1 + 25*0.10 + 15*0.50 + 15*0.50 = 45 + 2.5 + 7.5 + 7.5  = 62.5
Non-KEV CRITICAL:        45*0 + 25*0.10 + 15*0.98 + 15*0.50 =  0 + 2.5 + 14.7 + 7.5 = 24.7
```

The KEV-listed finding wins, by a wide margin, *despite* a lower severity
rating and no EPSS advantage. This is tested explicitly and literally in
`src/scoring/score.test.ts` ("the core value proposition") and again through
the full parse -> merge -> score pipeline against real trimmed EPSS/KEV data
in `src/merge/merge.test.ts` and `src/cli/cli.test.ts`.

Running the bundled fixtures through the real CLI shows the same effect on
a mixed report:

```
$ vulntriage --input test/fixtures/trivy-report.json --format trivy \
    --epss-file test/fixtures/epss-snapshot.csv --kev-file test/fixtures/kev-snapshot.json \
    --assets test/fixtures/assets.json

#1  CVE-2021-44228  score=100.00  ...   KEV=YES severity=CRITICAL
#2  CVE-2020-1472   score=93.10   ...   KEV=YES severity=MEDIUM      <- KEV, ranks #2
#3  CVE-2023-38545  score=49.32   ...   KEV=no  severity=CRITICAL    <- non-KEV critical, ranks #3
#4  CVE-2023-0048   score=34.32   ...   KEV=no  severity=HIGH
#5  CVE-9999-0001   score=19.50   ...   KEV=no  severity=LOW  (no EPSS record)
```

`CVE-2020-1472` (real, genuinely KEV-listed) outranks `CVE-2023-38545` (real,
genuinely CRITICAL, genuinely absent from the KEV catalog) even though the
sample scanner report rates it only MEDIUM - see
`test/fixtures/README.md` for exactly why that particular finding is
labeled that way in the fixture.

Ties (equal `total`) are broken deterministically by CVE id, then target, so
identical input always produces byte-identical output - there is no
randomness, no clock dependency, and no hidden state anywhere in the ranking.

## Supported scanner formats

- **Trivy** JSON (`trivy image/fs/repo -f json`) - the real schema documented at
  https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/#json.
  Auto-detected by the top-level `SchemaVersion` + `Results` shape.
- **Grype** JSON (`grype <target> -o json`) - Anchore's real schema
  (https://github.com/anchore/grype). Auto-detected by the top-level
  `matches` array.

Both parsers live in `src/parsers/` and normalize into the same
scanner-agnostic `ScannerFinding` shape (`src/types.ts`), so scoring/merging
never has to know which scanner produced a finding.

## Real data sources

- **EPSS** (Exploit Prediction Scoring System): the real FIRST.org API
  (`https://api.first.org/data/v1/epss`), the same daily-published scores
  as the bulk CSV at `https://epss.cyentia.com/epss_scores-current.csv.gz`.
  `src/sources/epss.ts` has a real `HttpEpssClient` (live API) and a real
  `FileEpssClient` (local CSV, same format as the bulk file) behind one
  `EpssClient` interface, so the CLI/tests can swap transports without
  touching any calling code.
- **CISA KEV**: the real catalog JSON at
  `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
  `src/sources/kev.ts` mirrors the same pattern (`HttpKevClient` /
  `FileKevClient`).

Both real HTTP clients take an injectable fetch function
(`src/sources/httpFetcher.ts`, defaulting to Node's built-in global
`fetch`), the same dependency-injection pattern used elsewhere in this
author's tooling for testable network clients. The default `npm test` run
is fully hermetic/offline - it exercises the real parsing/merge/scoring
logic against small, real, trimmed snapshots of both upstream files (see
`test/fixtures/README.md` for exact provenance). A separate, explicit
`npm run test:live` opts into hitting the real live endpoints, to verify the
HTTP clients still work against the real world on demand, without ever
making that a silent dependency of CI.

## Extension points (not implemented in v1)

The core product is deliberately formula-only - no ML, no LLM, fully
deterministic and auditable. A natural, explicitly optional extension for a
future version would be a plain-language "why this matters" note generated
per finding (e.g. summarizing the KEV/EPSS/severity inputs into a sentence).
That is intentionally out of scope for v1: the numeric breakdown already
*is* the explanation, and anything generative would need to be clearly
separated from - and never override - the deterministic score.

## Limitations

- **EPSS coverage.** Not every CVE has an EPSS score (very new CVEs in
  particular can lag by a few days). VulnTriage treats a missing EPSS
  record as `0`, i.e. "no evidence either way" - a conservative default,
  not a claim that the CVE is safe. If EPSS scoring lags behind disclosure
  for a genuinely dangerous new CVE, VulnTriage will under-rank it until
  EPSS catches up (or until it lands on KEV, which is scored independently).
- **KEV is inherently a lagging indicator.** CISA adds a CVE to KEV only
  after confirming active exploitation - by definition, day-zero of a new
  campaign is never KEV-listed yet. VulnTriage's heavy KEV weighting is a
  bet that CVEs already known to be under active exploitation matter more
  than CVEs that merely could be, which is a claim about typical operational
  risk, not a guarantee about any single CVE today.
- **Severity normalization is a simplification.** CVSS base scores ignore
  environmental/temporal context (network exposure, compensating controls,
  exploit maturity beyond EPSS). The fallback severity-bucket mapping
  (CRITICAL=0.9 ... UNKNOWN=0.1) is a reasonable default, not a substitute
  for a real CVSS vector when one is available.
- **Grype's "Negligible" severity has no direct equivalent** in VulnTriage's
  five-bucket `Severity` type and is folded into `UNKNOWN` (see
  `src/parsers/grype.ts`), which slightly understates it relative to `LOW`.
- **Only CVE-keyed lookups.** EPSS and KEV matching is purely by CVE id.
  Findings with only a GHSA/vendor advisory id and no CVE alias will never
  match either data source and will score as if neither applied.
- **No de-duplication across scanners.** Running both a Trivy and a Grype
  report through the same invocation (as the test suite does, for coverage)
  will list the same real-world vulnerability twice if both scanners found
  it - VulnTriage ranks findings, not unique CVEs across a fleet.
- **The bundled fixtures use one deliberately illustrative severity.** See
  `test/fixtures/README.md`: `CVE-2020-1472` is labeled `MEDIUM` in the
  sample Trivy report specifically to exercise the KEV-outranks-severity
  behavior in tests, even though its real-world CVSS/NVD severity is
  CRITICAL. This affects only the test fixtures, not any shipped code path.
- **CISA KEV and EPSS are US-government/FIRST.org-curated signals.** They
  are widely used industry references, not the only valid measures of
  exploitation risk, and neither publishes a formal SLA for update latency.

## Development

```bash
npm install
npm run build        # tsc -> dist/
npm run typecheck     # strict typecheck of src/ and test/
npm test              # vitest run - hermetic, offline, ~80 tests
npm run test:live     # opt-in: hits the real EPSS API + real KEV feed
```

Project layout:

```
src/
  types.ts            core domain types
  parsers/            trivy.ts, grype.ts, + format dispatch
  sources/            epss.ts, kev.ts (Http*Client + File*Client), httpFetcher.ts
  scoring/            score.ts - the formula, and only the formula
  merge/              assets.ts (criticality matching), merge.ts (merge + rank)
  cli/                index.ts (commander wiring), format.ts (text/json renderers)
bin/vulntriage.js     npm bin entry point (imports dist/)
test/fixtures/        real, trimmed EPSS/KEV snapshots + sample scanner reports
test/live/            opt-in live-network verification (not part of `npm test`)
```

## License

MIT © 2026 VulnTriage contributors. See [LICENSE](LICENSE).
