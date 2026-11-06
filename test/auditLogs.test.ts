import { describe, expect, it } from "vitest";
import fixture from "./fixtures/audit-v2.json";
import { categorise, processEntries, type AuditEntry } from "../src/collectors/auditLogs";

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
    expect(findings.find((f) => f.summary.includes("DNS record"))).toMatchObject({ severity: "info", zone: "example.test" });
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
