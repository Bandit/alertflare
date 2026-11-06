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
}

export interface Classifier {
  classify(g: SecurityEventGroup): Verdict;
}

/**
 * Noise:       path matches the ignore list. Never alerted, only counted.
 * Interesting: path under an "interesting" prefix (default /api/*), OR a
 *              state-changing method (POST etc.), OR >= asnRepeatThreshold
 *              hits in this fingerprint (fingerprints include the ASN).
 * Boring:      everything else (single-digit GETs of "/" from random places).
 *
 * Severity: "warning" when a non-noise /api/ path or a write method is being
 * blocked (that is what a silently-broken integration looks like),
 * "info" for repeated-ASN-only hits.
 */
export function makeClassifier(config: Config): Classifier {
  const isNoise = makeMatcher(config.ignorePaths);
  const isInterestingPath = makeMatcher(config.interestingPaths);
  const methods = new Set(config.interestingMethods);

  return {
    classify(g) {
      if (isNoise(g.path)) return { kind: "noise", reason: "ignore-list" };
      const reasons: string[] = [];
      let severity: Severity = "info";
      if (isInterestingPath(g.path)) {
        reasons.push("interesting path");
        severity = "warning";
      }
      if (methods.has(g.method.toUpperCase())) {
        reasons.push(`${g.method.toUpperCase()} request`);
        severity = "warning";
      }
      if (g.count >= config.asnRepeatThreshold) {
        reasons.push(`${g.count} hits from one ASN`);
      }
      if (reasons.length === 0) return { kind: "boring" };
      return { kind: "interesting", severity, reasons };
    },
  };
}
