/** Public library API surface for consuming VulnTriage programmatically
 * instead of via the CLI. */

export * from './types.js';
export * from './scoring/score.js';
export * from './merge/assets.js';
export * from './merge/merge.js';
export * from './parsers/index.js';
export * from './sources/httpFetcher.js';
export * from './sources/epss.js';
export * from './sources/kev.js';
