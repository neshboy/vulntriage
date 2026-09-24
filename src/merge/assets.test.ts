import { describe, expect, it } from 'vitest';
import { matchAssetCriticality, validateAssetCriticalityConfig } from './assets.js';
import type { AssetCriticalityConfig } from '../types.js';

describe('matchAssetCriticality', () => {
  const config: AssetCriticalityConfig = {
    defaultCriticality: 'medium',
    assets: [
      { match: 'prod-db*', criticality: 'critical' },
      { match: 'legacy-app:2.1.0', criticality: 'low' },
    ],
  };

  it('matches an exact target string', () => {
    expect(matchAssetCriticality('legacy-app:2.1.0', config)).toBe('low');
  });

  it('matches a `*`-wildcard glob prefix', () => {
    expect(matchAssetCriticality('prod-db:1.0.0', config)).toBe('critical');
    expect(matchAssetCriticality('prod-db-replica-02', config)).toBe('critical');
  });

  it('falls back to defaultCriticality when nothing matches', () => {
    expect(matchAssetCriticality('some-random-service', config)).toBe('medium');
  });

  it('evaluates rules in order, first match wins', () => {
    const orderedConfig: AssetCriticalityConfig = {
      defaultCriticality: 'low',
      assets: [
        { match: '*', criticality: 'high' },
        { match: 'specific-app', criticality: 'critical' },
      ],
    };
    // The catch-all "*" rule comes first, so it wins even for "specific-app".
    expect(matchAssetCriticality('specific-app', orderedConfig)).toBe('high');
  });

  it('escapes regex metacharacters in the match pattern other than `*`', () => {
    const dotConfig: AssetCriticalityConfig = {
      defaultCriticality: 'medium',
      assets: [{ match: 'app.name:1.0', criticality: 'high' }],
    };
    // A literal dot should not match "appXname:1.0" the way an unescaped
    // regex "." would.
    expect(matchAssetCriticality('appXname:1.0', dotConfig)).toBe('medium');
    expect(matchAssetCriticality('app.name:1.0', dotConfig)).toBe('high');
  });
});

describe('validateAssetCriticalityConfig', () => {
  it('accepts a well-formed config', () => {
    const parsed = validateAssetCriticalityConfig({
      defaultCriticality: 'low',
      assets: [{ match: 'x', criticality: 'high' }],
    });
    expect(parsed.defaultCriticality).toBe('low');
    expect(parsed.assets).toEqual([{ match: 'x', criticality: 'high' }]);
  });

  it('defaults assets to an empty array when omitted', () => {
    const parsed = validateAssetCriticalityConfig({ defaultCriticality: 'medium' });
    expect(parsed.assets).toEqual([]);
  });

  it('rejects a non-object input', () => {
    expect(() => validateAssetCriticalityConfig('nope')).toThrow(/must be a JSON object/);
  });

  it('rejects an invalid defaultCriticality', () => {
    expect(() => validateAssetCriticalityConfig({ defaultCriticality: 'urgent' })).toThrow(/defaultCriticality/);
  });

  it('rejects a rule with an invalid criticality tag', () => {
    expect(() =>
      validateAssetCriticalityConfig({ defaultCriticality: 'medium', assets: [{ match: 'x', criticality: 'urgent' }] }),
    ).toThrow(/assets\[0\]\.criticality/);
  });

  it('rejects a rule with a missing match pattern', () => {
    expect(() =>
      validateAssetCriticalityConfig({ defaultCriticality: 'medium', assets: [{ criticality: 'high' }] }),
    ).toThrow(/assets\[0\]\.match/);
  });
});
