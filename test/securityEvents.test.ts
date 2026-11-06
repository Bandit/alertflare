import { describe, expect, it } from "vitest";
import groupsFixture from "./fixtures/graphql-groups.json";
import rawFixture from "./fixtures/graphql-raw.json";
import {
  aggregate, buildFilters, globToLike, isMitigation, parseGroupsZone, parseRawZone,
  type ZoneGroupsData, type ZoneRawData,
} from "../src/collectors/securityEvents";
import { makeClassifier } from "../src/lib/classify";
import { testConfig } from "./helpers";

const classifier = makeClassifier(testConfig());

describe("isMitigation", () => {
  it.each(["block", "challenge", "jschallenge", "managed_challenge", "managedchallenge", "connectionclose", "connection_close"])("%s counts", (a) =>
    expect(isMitigation(a)).toBe(true));
  it.each(["log", "allow", "skip", "bypass", "challenge_solved", "managed_challenge_interactive_solved", "jschallengesolved"])("%s does not", (a) =>
    expect(isMitigation(a)).toBe(false));
});

describe("parseGroupsZone + aggregate (Pro: Groups dataset)", () => {
  const zd = groupsFixture.data.viewer.zones[0] as ZoneGroupsData;
  const parsed = parseGroupsZone("example.test", zd);

  it("reads the total and drops solved challenges", () => {
    expect(parsed.total).toBe(4210);
    expect(parsed.rows.find((r) => r.action.includes("solved"))).toBeUndefined();
  });

  const { findings, stats } = aggregate(parsed.rows, classifier);

  it("groups one integration's webhook calls into one fingerprint (across countries)", () => {
    const hook = findings.filter((f) => f.summary.includes("/api/webhook/{id}"));
    expect(hook).toHaveLength(1);
    expect(hook[0]!.count).toBe(136);
    expect(hook[0]!.severity).toBe("urgent");
    expect(hook[0]!.summary).toBe('POST /api/webhook/{id} on app.example.test: block by Custom rule "Block suspicious traffic"');
    expect(hook[0]!.details!.join(" ")).toContain("AS16509 AMAZON-02 (IE, FR)");
    expect(hook[0]!.rayId).toBe("8f00aa11bb22cc33");
  });

  it("never leaks the full webhook id", () => {
    const text = JSON.stringify(findings);
    expect(text).not.toContain("3f9a12bc0d4e5f60718293a4b5c6d7e8f90a1b2c");
    expect(text).toContain("3f9a12bc…");
  });

  it("treats a high-volume single ASN as info, scanner paths as noise", () => {
    const root = findings.find((f) => f.summary.startsWith("GET / "));
    expect(root?.severity).toBe("info");
    expect(findings.find((f) => f.summary.includes(".env"))).toBeUndefined();
    expect(findings.find((f) => f.summary.includes("/auth/authorize"))).toBeUndefined(); // 7 GETs = boring
    expect(stats["example.test"]).toMatchObject({ noise: 12, boring: 7, interesting: 3136 });
  });

  it("produces dashboard links without account or zone IDs", () => {
    for (const f of findings) {
      expect(f.link).toMatch(/^https:\/\/dash\.cloudflare\.com\/\?to=\/:account\/example\.test\//);
      expect(f.link).not.toMatch(/[0-9a-f]{32}/);
    }
  });
});

describe("parseRawZone (Free: raw events dataset)", () => {
  const zd = rawFixture.data.viewer.zones[0] as ZoneRawData;
  const parsed = parseRawZone("blog.example.test", zd);
  it("weights by sampleInterval, drops log actions", () => {
    // fixture paths are below MIN_HITS=3 individually; aggregate to 3
    expect(parsed.rows).toHaveLength(3);
    const { findings } = aggregate(parsed.rows, classifier);
    const api = findings.find((f) => f.summary.includes("/api/v1/items/{n}"));
    expect(api?.count).toBe(3);
    expect(api?.rayId).toBe("8f00aa11bb22cc44");
  });
  it("catches mixed-case scanner paths client-side", () => {
    const { findings, stats } = aggregate(parsed.rows, classifier);
    expect(findings.find((f) => f.summary.toLowerCase().includes("wp-login"))).toBeUndefined();
    expect(stats["blog.example.test"]!.noise).toBe(1);
  });
});

describe("GraphQL filters", () => {
  it("converts globs to LIKE patterns", () => {
    expect(globToLike("/wp-*")).toBe("/wp-%");
    expect(globToLike("*/.git/*")).toBe("%/.git/%");
  });
  it("builds a 24h filter with server-side noise exclusion", () => {
    const f = buildFilters(testConfig(), "2026-11-05T19:00:00Z", "2026-11-06T19:00:00Z");
    expect(f.total.AND).toContainEqual({ datetime_geq: "2026-11-05T19:00:00Z" });
    expect(f.filtered.AND).toContainEqual({ clientRequestPath_notlike: "/wp-%" });
    expect(f.total.AND).not.toContainEqual({ clientRequestPath_notlike: "/wp-%" });
    const or = (f.examples.AND.at(-1) as { OR: unknown[] }).OR;
    expect(or).toContainEqual({ clientRequestPath_like: "/api/%" });
  });
});

describe("hostname redaction", () => {
  it("truncates random-looking labels in summaries", async () => {
    const { redactHost } = await import("../src/lib/normalise");
    expect(redactHost("app-k3x9qw7vbn2mzp4rt8y.example.com")).toBe("app-k3x9….example.com");
    expect(redactHost("shop.example.com")).toBe("shop.example.com");
    expect(redactHost("www.example.test")).toBe("www.example.test");
  });
  it("is applied by aggregate() when enabled", async () => {
    const rows = [{ zone: "example.com", host: "app-k3x9qw7vbn2mzp4rt8y.example.com", action: "block", source: "firewallCustom", ruleId: "r", description: "Custom", method: "POST", path: "/api/webhook/x", asn: "8075", asnName: "MICROSOFT", country: "NL", count: 93 }];
    const { findings } = aggregate(rows, classifier, { redactHostnames: true });
    expect(findings[0]!.summary).toContain("on app-k3x9….example.com");
    // The fingerprint (KV only) keeps the full host; the rendered email must not.
    const { renderDigest } = await import("../src/lib/digest");
    const msg = renderDigest(findings.map((f) => ({ ...f, reason: "new" as const })), { title: "t", date: "d" })!;
    expect(msg.text + msg.subject).not.toContain("k3x9qw7vbn2mzp4rt8y");
  });
});
