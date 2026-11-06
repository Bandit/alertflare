import { describe, expect, it } from "vitest";
import { makeClassifier } from "../src/lib/classify";
import { testConfig } from "./helpers";

describe("classifier", () => {
  const c = makeClassifier(testConfig());
  it("never alerts on ignore-list paths, even POSTs with huge volume", () => {
    expect(c.classify({ path: "/wp-login.php", method: "POST", count: 10_000 }).kind).toBe("noise");
  });
  it("flags blocked webhook POSTs as warning", () => {
    const v = c.classify({ path: "/api/webhook/abc", method: "POST", count: 3, source: "firewallCustom" });
    expect(v).toMatchObject({ kind: "interesting", severity: "warning" });
  });
  it("makes the broken-webhook pattern (webhook POSTs blocked all day) urgent", () => {
    const v = c.classify({ path: "/api/webhook/abc", method: "POST", count: 93, source: "firewallCustom" });
    expect(v).toMatchObject({ kind: "interesting", severity: "urgent" });
  });
  it("flags any /api/ path", () => {
    expect(c.classify({ path: "/api/states", method: "GET", count: 3 })).toMatchObject({ kind: "interesting", severity: "warning" });
  });
  it("ignores one-off probes below MIN_HITS", () => {
    expect(c.classify({ path: "/api/config", method: "GET", count: 1, source: "firewallCustom" }).kind).toBe("boring");
    expect(c.classify({ path: "/graphql", method: "POST", count: 2, source: "firewallCustom" }).kind).toBe("boring");
  });
  it("treats managed-rule exploit probes quietly (live: React/WordPress RCE on POST /)", () => {
    expect(c.classify({ path: "/", method: "POST", count: 18, source: "firewallManaged" }).kind).toBe("boring");
    expect(c.classify({ path: "/api/system/fileView", method: "GET", count: 3, source: "firewallManaged" }).kind).toBe("boring");
    // ...but a managed-rule false positive on a webhook is still caught
    expect(c.classify({ path: "/api/webhook/abc", method: "POST", count: 5, source: "firewallManaged" })).toMatchObject({ kind: "interesting", severity: "warning" });
    // ...and so is sheer volume
    expect(c.classify({ path: "/", method: "POST", count: 500, source: "firewallManaged" })).toMatchObject({ kind: "interesting", severity: "info" });
  });
  it("treats path traversal probes as noise", () => {
    expect(c.classify({ path: "/api/w/starter/jobs_u/get_log_file/../../../../proc/self/environ", method: "GET", count: 9 }).kind).toBe("noise");
    expect(c.classify({ path: "/api/env", method: "GET", count: 9 }).kind).toBe("noise");
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
