# Test fixtures: provenance

These fixtures back the hermetic/offline test suite (no network access
required to run `npm test`). Where they contain real upstream data, that
data was live-fetched from the real endpoints during development:

- **`epss-snapshot.csv`** - an exact, trimmed excerpt of the real EPSS bulk
  CSV published at `https://epss.cyentia.com/epss_scores-current.csv.gz`,
  fetched live on 2026-09-24. The header comment line
  (`#model_version:v2026.06.15,score_date:2026-09-23T12:00:20Z`) and every
  data row are copied verbatim from that real file for the CVE ids used in
  the other fixtures below - scores were not hand-typed or invented.

- **`kev-snapshot.json`** - a trimmed subset (7 of 1721 entries) of the real
  CISA Known Exploited Vulnerabilities catalog, fetched live on 2026-09-24
  from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
  Each entry is copied verbatim (same schema, same field values) from that
  live response.

- **`trivy-report.json`** / **`grype-report.json`** - hand-authored sample
  scanner reports in each tool's real, documented JSON schema, referencing
  a mix of the real CVE ids above (so merge/scoring tests exercise real
  EPSS+KEV data) plus two obviously-fake placeholder ids (`CVE-9999-0001`,
  `CVE-9999-0002`, year 9999) used specifically to test the "no EPSS
  record / not KEV-listed" fallback path.

  One entry (`CVE-2020-1472`, Zerologon, in `trivy-report.json`) is
  deliberately labeled `Severity: "MEDIUM"` even though its real-world
  CVSS/NVD severity is CRITICAL. This is intentional fixture data, not a
  factual claim about that CVE: it exists purely so
  `test/merge.test.ts`/`test/cli.test.ts` can demonstrate, through the real
  merge+scoring pipeline (not just the isolated formula unit test in
  `src/scoring/score.test.ts`), that a KEV-listed finding outranks a
  same-report non-KEV CRITICAL finding (`CVE-2023-38545`, curl SOCKS5 -
  genuinely CRITICAL-severity and genuinely absent from the live KEV
  catalog as of the fetch date above) regardless of the scanner's own
  severity label.

- **`assets.json`** - a hand-authored asset-criticality config used to
  exercise glob matching and the default-criticality fallback.
