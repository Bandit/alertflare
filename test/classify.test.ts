import { describe, expect, it } from "vitest";
import { makeClassifier } from "../src/lib/classify";
import { testConfig } from "./helpers";

describe("classifier", () => {
  const c = makeClassifier(testConfig());
  it("never alerts on ignore-list paths, even POSTs with huge volume", () => {
    expect(c.classify({ path: "/wp-login.php", method: "POST", count: 10_000 }).kind).toBe("noise");
  });
  it("flags blocked webhook POSTs as warning", () => {
    const v = c.classify({ path: "/api/webhook/abc", method: "POST", count: 1 });
    expect(v).toMatchObject({ kind: "interesting", severity: "warning" });
  });
  it("flags any /api/ path", () => {
    expect(c.classify({ path: "/api/states", method: "GET", count: 1 })).toMatchObject({ kind: "interesting", severity: "warning" });
  });
  it("flags repeated hits from one ASN as info", () => {
    expect(c.classify({ path: "/", method: "GET", count: 50 })).toMatchObject({ kind: "interesting", severity: "info" });
  });
  it("ignores low-volume GETs of ordinary paths", () => {
    expect(c.classify({ path: "/", method: "GET", count: 3 }).kind).toBe("boring");
  });
  it("respects configuration", () => {
    const c2 = makeClassifier(testConfig({ ASN_REPEAT_THRESHOLD: "5", EXTRA_IGNORE_PATHS: "/api/legacy/*" }));
    expect(c2.classify({ path: "/", method: "GET", count: 5 }).kind).toBe("interesting");
    expect(c2.classify({ path: "/api/legacy/x", method: "POST", count: 1 }).kind).toBe("noise");
  });
});
