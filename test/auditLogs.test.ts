import { describe, expect, it } from "vitest";
import fixture from "./fixtures/audit-v2.json";
import { categorise, processEntries, shortId, type AuditEntry } from "../src/collectors/auditLogs";

const entries = fixture.result as AuditEntry[];
const opts = { urgentOnly: false, timezone: "UTC" };

describe("audit log categorisation", () => {
  it("recognises tokens, logins, DNS and rulesets", () => {
    expect(entries.map(categorise)).toEqual(["token", "dns", "login", "login", "other", "security"]);
  });
});

describe("processEntries", () => {
  it("first run: reports changes, seeds login IPs silently, skips views", () => {
    const { findings, state, stats } = processEntries(entries, undefined, opts);
    const summaries = findings.map((f) => f.summary);
    expect(summaries).toHaveLength(3);
    expect(findings.find((f) => f.summary.includes("Create API token"))?.severity).toBe("urgent");
    expect(findings.find((f) => f.summary.includes("custom ruleset"))?.severity).toBe("warning");
    expect(findings.find((f) => f.summary.includes("dns_records change"))).toMatchObject({ severity: "info", zone: "example.test" });
    expect(summaries.some((s) => s.includes("List zones"))).toBe(false);
    expect(state.loginIps["owner@example.test"]).toEqual(["203.0.113.10", "198.51.100.77"]);
    expect(stats).toMatchObject({ logins: 2, changes: 3 });
  });

  it("later runs: a login from a new IP is urgent, from a known IP is silent", () => {
    const prev = { loginIps: { "owner@example.test": ["203.0.113.10"] } };
    const { findings } = processEntries(entries, prev, opts);
    const logins = findings.filter((f) => f.summary.startsWith("Login"));
    expect(logins).toHaveLength(1);
    expect(logins[0]).toMatchObject({ severity: "urgent", summary: "Login from NEW IP: owner@example.test" });
  });

  it("hourly mode only emits urgent items", () => {
    const { findings } = processEntries(entries, { loginIps: {} }, { ...opts, urgentOnly: true });
    expect(findings.every((f) => f.severity === "urgent")).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("never includes request/response bodies or long ids", () => {
    const text = JSON.stringify(processEntries(entries, undefined, opts).findings);
    expect(text).not.toContain("SECRET-TOKEN-VALUE");
    expect(text).not.toContain("should-never-appear");
    expect(text).not.toContain("a1b2c3d4e5f6a7b8c9d0");
    expect(text).toContain("a1b2c3d4…");
  });

  it("failed logins are urgent even from known IPs", () => {
    const failed: AuditEntry = { ...entries[2]!, id: "x", action: { ...entries[2]!.action, result: "failure" } };
    const { findings } = processEntries([failed], { loginIps: { "owner@example.test": ["203.0.113.10"] } }, opts);
    expect(findings[0]).toMatchObject({ severity: "urgent" });
    expect(findings[0]!.summary).toContain("FAILED");
  });
});

describe("noise reduction (shapes seen on a live account)", () => {
  const mk = (id: string, description: string, product: string, actorType = "user", extra: Partial<AuditEntry> = {}): AuditEntry => ({
    id,
    action: { description, result: "success", time: `2026-11-05T2${id.length % 10}:00:00Z`, type: "create" },
    actor: { email: actorType === "user" ? "owner@example.test" : undefined, type: actorType, context: "oauth" },
    resource: { product },
    ...extra,
  });
  const live = [
    mk("1", "Query D1 Database", "d1"),
    mk("2", "Execute an Analytics Engine SQL query via request", "analytics_engine"),
    mk("3", "Upload Worker Assets", "workers", "delegated_service"),
    mk("4", "", "dns", "system"),
    mk("5", "Upload Version", "workers"),
    mk("6", "Create Worker Deployment", "workers"),
    mk("7", "Upload Version", "workers"),
    mk("8", "Create Worker Deployment", "workers"),
    mk("9", "Patch Worker Script Settings", "workers"),
  ];
  const opts = { urgentOnly: false, timezone: "UTC", now: new Date("2026-11-06T19:00:00Z") };

  it("drops data-plane operations and system/delegated actors", () => {
    const { findings, stats } = processEntries(live, { loginIps: {} }, opts);
    expect(stats.ignored).toBe(4);
    expect(JSON.stringify(findings)).not.toMatch(/D1|Analytics Engine|Assets/);
  });

  it("rolls info items up into one line per actor/product", () => {
    const { findings } = processEntries(live, { loginIps: {} }, opts);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.summary).toBe("owner@example.test: 5 workers changes");
    expect(findings[0]!.details![0]).toBe("Upload Version ×2, Create Worker Deployment ×2, Patch Worker Script Settings");
  });

  it("rollup fingerprint depends on the entries, not the run date", () => {
    const a = processEntries(live, { loginIps: {} }, opts).findings[0]!.fingerprint;
    const b = processEntries(live, { loginIps: {} }, { ...opts, now: new Date("2026-11-09T19:00:00Z") }).findings[0]!.fingerprint;
    expect(a).toBe(b);
    const c = processEntries(live.slice(0, 6), { loginIps: {} }, opts).findings[0]!.fingerprint;
    expect(c).not.toBe(a);
  });

  it("can include system actors and custom ignores", () => {
    const { stats } = processEntries(live, { loginIps: {} }, { ...opts, includeSystem: true, ignore: ["Upload Version"] });
    expect(stats.ignored).toBe(2);
  });

  it("keeps readable resource ids but truncates random ones", () => {
    expect(shortId("http_request_firewall_custom")).toBe("http_request_firewall_custom");
    expect(shortId("b6e6130c4d2e4f1a9c3b2a1d0e9f8a7b")).toBe("b6e6130c…");
  });
});
