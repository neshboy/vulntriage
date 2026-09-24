/**
 * The narrow slice of the standard `fetch` API that VulnTriage's real data
 * clients depend on. Both `HttpEpssClient` and `HttpKevClient` take one of
 * these as a constructor argument (defaulting to the real global `fetch`),
 * which is the same dependency-injection pattern used elsewhere in this
 * portfolio (e.g. certwatch's crt.sh client, greenlight's DNS lookup) to
 * keep the default test suite hermetic/offline while the production code
 * path still makes real network calls.
 */
export type FetchLike = typeof fetch;

/** The real fetcher: Node's built-in global `fetch` (available unmodified
 * since Node 18). Exists as a named export purely so callers/tests can
 * `import { realFetch }` instead of reaching for the ambient global. */
export const realFetch: FetchLike = fetch;
