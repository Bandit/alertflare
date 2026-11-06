import { describe, expect, it } from "vitest";
import fixture from "./fixtures/access-requests.json";
import { isNotSetUp, processAccessRequests, type AccessRequest } from "../src/collectors/access";
import { CloudflareApiError } from "../src/cf/client";

describe("processAccessRequests", () => {
  const { findings, stats } = processAccessRequests(fixture.result as AccessRequest[]);
  it("groups denials by app, identity (case-insensitive) and country", () => {
    expect(stats).toEqual({ requests: 4, denied: 3 });
    expect(findings).toHaveLength(2);
    const app = findings.find((f) => f.summary.includes("app.example.test"))!;
    expect(app.count).toBe(2);
    expect(app.summary).toBe("Access denied: stranger@example.org → app.example.test (US)");
    expect(app.details![0]).toContain("2 IPs");
  });
  it("handles denials with no identity", () => {
    expect(findings.find((f) => f.summary.includes("(no identity)"))).toBeDefined();
  });
});

describe("isNotSetUp", () => {
  it("distinguishes 'Access not enabled' from a permissions problem", () => {
    expect(isNotSetUp(new CloudflareApiError("x: 404", 404))).toBe(true);
    expect(isNotSetUp(new CloudflareApiError("x: access.api.error.not_enabled: Access is not enabled", 403, [12006]))).toBe(true);
    expect(isNotSetUp(new CloudflareApiError("x: 10000 Authentication error", 403, [10000]))).toBe(false);
    expect(isNotSetUp(new Error("boom"))).toBe(false);
  });
});
