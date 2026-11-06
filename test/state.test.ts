import { describe, expect, it } from "vitest";
import { diffFindings, type ReportedState } from "../src/lib/state";
import type { Finding } from "../src/types";

const opts = (now: number) => ({ volumeJumpMultiplier: 3, volumeJumpMinCount: 20, forgetAfterDays: 30, now });
const f = (fp: string, count: number, kind: Finding["kind"] = "recurring"): Finding => ({
  source: "s", fingerprint: fp, severity: "warning", summary: fp, zone: "z", count, kind,
});
const DAY = 86_400_000;

describe("diffFindings", () => {
  it("reports new fingerprints once", () => {
    const a = diffFindings([f("a", 10)], {}, opts(0));
    expect(a.toReport.map((x) => x.reason)).toEqual(["new"]);
    const b = diffFindings([f("a", 12)], a.next, opts(DAY));
    expect(b.toReport).toEqual([]);
  });
  it("re-reports when volume jumps by the multiplier", () => {
    const a = diffFindings([f("a", 10)], {}, opts(0));
    const b = diffFindings([f("a", 29)], a.next, opts(DAY));
    expect(b.toReport).toEqual([]);
    const c = diffFindings([f("a", 30)], b.next, opts(2 * DAY));
    expect(c.toReport[0]).toMatchObject({ reason: "volume-jump", previousCount: 10 });
    // baseline moves up
    expect(diffFindings([f("a", 60)], c.next, opts(3 * DAY)).toReport).toEqual([]);
  });
  it("ignores jumps below the minimum count", () => {
    const a = diffFindings([f("a", 1)], {}, opts(0));
    expect(diffFindings([f("a", 10)], a.next, opts(DAY)).toReport).toEqual([]);
  });
  it("never re-reports one-off events or acknowledged entries", () => {
    const a = diffFindings([f("e", 1, "event")], {}, opts(0));
    expect(diffFindings([f("e", 1000, "event")], a.next, opts(DAY)).toReport).toEqual([]);
    const acked: ReportedState = { "s|a": { c: 1, f: 0, s: 0, a: 1 } };
    expect(diffFindings([f("a", 1000)], acked, opts(DAY)).toReport).toEqual([]);
  });
  it("forgets fingerprints unseen for forgetAfterDays", () => {
    const a = diffFindings([f("a", 10)], {}, opts(0));
    const b = diffFindings([], a.next, opts(31 * DAY));
    expect(b.next).toEqual({});
    expect(diffFindings([f("a", 10)], b.next, opts(32 * DAY)).toReport).toHaveLength(1);
  });
  it("only marks state changed when needed (KV write budget)", () => {
    const a = diffFindings([f("a", 10)], {}, opts(0));
    expect(diffFindings([f("a", 10)], a.next, opts(1000)).changed).toBe(false);
  });
  it("merges duplicate fingerprints within one run", () => {
    const a = diffFindings([f("a", 10), f("a", 15)], {}, opts(0));
    expect(a.toReport).toHaveLength(1);
    expect(a.toReport[0]!.count).toBe(25);
  });
});
