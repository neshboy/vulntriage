import type { AssetCriticalityConfig, CriticalityTag } from '../types.js';

/** Compile a `*`-wildcard glob pattern (the only wildcard VulnTriage asset
 * rules support) into an anchored, fully-escaped RegExp. */
function globToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // escape regex metacharacters
    .replace(/\*/g, '.*'); // then reintroduce `*` as a wildcard
  return new RegExp(`^${escaped}$`);
}

/** Resolve the criticality tag for a scan target against a user-supplied
 * asset-criticality config. Rules are evaluated in file order and the
 * first match wins; if no rule matches, `defaultCriticality` applies. */
export function matchAssetCriticality(target: string, config: AssetCriticalityConfig): CriticalityTag {
  for (const rule of config.assets) {
    if (globToRegExp(rule.match).test(target)) {
      return rule.criticality;
    }
  }
  return config.defaultCriticality;
}

const VALID_TAGS: ReadonlySet<string> = new Set(['critical', 'high', 'medium', 'low']);

/** Validate a parsed asset-criticality config, throwing a descriptive error
 * on malformed input (unknown criticality tag, missing fields, etc.) so CLI
 * users get an actionable message instead of a downstream type error. */
export function validateAssetCriticalityConfig(value: unknown): AssetCriticalityConfig {
  if (typeof value !== 'object' || value === null) {
    throw new Error('Asset-criticality config must be a JSON object');
  }
  const obj = value as Record<string, unknown>;

  const defaultCriticality = obj.defaultCriticality;
  if (typeof defaultCriticality !== 'string' || !VALID_TAGS.has(defaultCriticality)) {
    throw new Error(
      `Asset-criticality config "defaultCriticality" must be one of critical|high|medium|low (got: ${String(defaultCriticality)})`,
    );
  }

  const rawAssets = obj.assets;
  if (rawAssets !== undefined && !Array.isArray(rawAssets)) {
    throw new Error('Asset-criticality config "assets" must be an array if present');
  }

  const assets = (rawAssets ?? []).map((raw, i) => {
    if (typeof raw !== 'object' || raw === null) {
      throw new Error(`Asset-criticality config assets[${i}] must be an object`);
    }
    const rule = raw as Record<string, unknown>;
    if (typeof rule.match !== 'string' || rule.match.length === 0) {
      throw new Error(`Asset-criticality config assets[${i}].match must be a non-empty string`);
    }
    if (typeof rule.criticality !== 'string' || !VALID_TAGS.has(rule.criticality)) {
      throw new Error(
        `Asset-criticality config assets[${i}].criticality must be one of critical|high|medium|low (got: ${String(rule.criticality)})`,
      );
    }
    return { match: rule.match, criticality: rule.criticality as CriticalityTag };
  });

  return { defaultCriticality: defaultCriticality as CriticalityTag, assets };
}
