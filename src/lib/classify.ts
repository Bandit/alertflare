import type { Config } from "../config";
import type { Severity } from "../types";
import { makeMatcher } from "./normalise";

export type Verdict =
  | { kind: "noise"; reason: string }
  | { kind: "boring" }
  | { kind: "interesting"; severity: Severity; reasons: string[] };

export interface SecurityEventGroup {
  path: string; // raw path (one example)
  method: string;
  count: number;
  /** GraphQL `source`, e.g. firewallCustom, firewallManaged */
  source?: string;
}

export interface Classifier {
  classify(g: SecurityEventGroup): Verdict;
}

/**
 * Rules you wrote yourself (custom rules, rate limits, IP/ASN/country access
 * rules, zone lockdown, UA blocks). A block here may be YOUR rule catching
 * legitimate traffic, which is the broken-webhook failure mode. Everything else
 * (managed rulesets, bot detections, DDoS, security level, ...) is
 * Cloudflare detecting an attack signature, so it is treated more quietly.
 */
export const DEFAULT_OWN_RULE_SOURCES = [
  "firewallCustom",
  "firewallrules",
  "ratelimit",
  "ratelimitingrules",
  "ip",
  "iprange",
  "asn",
  "country",
  "zonelockdown",
  "uablock",
];

/**
 * Noise:       path matches the ignore list. Never alerted, only counted.
 *
 * Own-rule sources (custom rules etc.), interesting when:
 *   - path matches INTERESTING_PATHS (default /api/*) or method is a write
 *     method, AND there were at least MIN_HITS hits (default 3; one-off
 *     scanner probes are 1-3 hits, real integrations retry all day), OR
 *   - >= ASN_REPEAT_THRESHOLD hits on the fingerprint (which includes ASN).
 *
 * Cloudflare-detection sources (managed rules, bots, ...), interesting when:
 *   - interesting path AND write method AND >= MIN_HITS
 *     (e.g. a managed rule false-positive on an integration's webhook), OR
 *   - >= ASN_REPEAT_THRESHOLD hits.
 *   Exploit probes like `POST /` matching a CVE signature are therefore
 *   counted but not reported.
 *
 * Severity:
 *   urgent  - interesting path + write method + ASN threshold reached:
 *             an integration is retrying and being blocked all day.
 *   warning - interesting path or write method.
 *   info    - volume (ASN threshold) only.
 */
export function makeClassifier(config: Config): Classifier {
  const isNoise = makeMatcher(config.ignorePaths);
  const isInterestingPath = makeMatcher(config.interestingPaths);
  const methods = new Set(config.interestingMethods);
  const own = new Set(config.ownRuleSources.map((s) => s.toLowerCase()));

  return {
    classify(g) {
      if (isNoise(g.path)) return { kind: "noise", reason: "ignore-list" };
      const ownRule = g.source === undefined || own.has(g.source.toLowerCase());
      const pathHit = isInterestingPath(g.path);
      const methodHit = methods.has(g.method.toUpperCase());
      const enough = g.count >= config.minHits;
      const volume = g.count >= config.asnRepeatThreshold;

      const reasons: string[] = [];
      if (pathHit) reasons.push("interesting path");
      if (methodHit) reasons.push(`${g.method.toUpperCase()} request`);
      if (volume) reasons.push(`${g.count} hits from one ASN`);

      const signal = ownRule ? (pathHit || methodHit) && enough : pathHit && methodHit && enough;
      if (!signal && !volume) return { kind: "boring" };

      let severity: Severity = "info";
      if (signal) severity = "warning";
      if (pathHit && methodHit && volume) severity = "urgent";
      return { kind: "interesting", severity, reasons };
    },
  };
}
