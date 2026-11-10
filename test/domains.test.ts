import { describe, expect, it } from "vitest";
import rdapFixture from "./fixtures/rdap-net.json";
import registrationsFixture from "./fixtures/registrations.json";
import whoisText from "./fixtures/whois-nz";
import {
  analyseDomain, createDomainsCollector, parseRdap, parseWhois, rdapBase,
  type ApiZone, type DomainsState, type RegistryInfo,
} from "../src/collectors/domains";
import { CloudflareClient } from "../src/cf/client";
import type { CollectorContext } from "../src/types";
import { jsonResponse, testConfig, testEnv } from "./helpers";

const NOW = Date.parse("2026-11-10T19:00:00Z");
const DAY = 86_400_000;
const opts = { now: NOW, expiryWarnDays: 30, date: "2026-11-10" };
const CF_NS = ["gerald.ns.cloudflare.com", "ulla.ns.cloudflare.com"];
const zone = (o: Partial<ApiZone> = {}): ApiZone => ({ id: "z1", name: "example.nz", status: "active", name_servers: CF_NS, ...o });
const whois = parseWhois(whoisText);

describe("parsing", () => {
  it("reads .nz WHOIS", () => {
    expect(whois).toEqual({ nameservers: CF_NS, registrar: "Example Registrar Ltd", statuses: ["ok"], signed: false, source: "whois" });
  });
  it("reads RDAP", () => {
    expect(parseRdap(rdapFixture as never)).toEqual({
      nameservers: CF_NS, registrar: "Cloudflare, Inc.", statuses: ["client transfer prohibited"], signed: false,
      expiresAt: "2027-10-14T16:50:13Z", source: "rdap",
    });
  });
  it("finds the RDAP base URL from the IANA bootstrap", () => {
    const services: [string[], string[]][] = [[["com", "net"], ["https://rdap.verisign.com/net/v1/"]], [["org"], ["https://rdap.org.example"]]];
    expect(rdapBase(services, "example.net")).toBe("https://rdap.verisign.com/net/v1/");
    expect(rdapBase(services, "x.org")).toBe("https://rdap.org.example/");
    expect(rdapBase(services, "example.nz")).toBeUndefined();
  });
});

describe("analyseDomain", () => {
  const run = (input: Parameters<typeof analyseDomain>[0], prev?: Parameters<typeof analyseDomain>[1]) => analyseDomain(input, prev, opts);

  it("is silent for a healthy domain", () => {
    expect(run({ zone: zone(), dnssec: "disabled", registry: whois }).findings).toEqual([]);
  });

  it("flags registry nameservers that differ from Cloudflare's (hijack check)", () => {
    const [f] = run({ zone: zone(), registry: { ...whois, nameservers: ["ns1.evil.example", "ns2.evil.example"] } }).findings;
    expect(f!.severity).toBe("urgent");
    expect(f!.details).toEqual([
      "registry: ns1.evil.example, ns2.evil.example",
      "Cloudflare: gerald.ns.cloudflare.com, ulla.ns.cloudflare.com",
      "If you didn't change this at your registrar, treat it as a possible domain hijack",
    ]);
  });

  it("reports moved and pending zones", () => {
    expect(run({ zone: zone({ status: "moved" }) }).findings[0]!.severity).toBe("urgent");
    expect(run({ zone: zone({ status: "pending" }) }).findings[0]!.summary).toBe('example.nz zone status is "pending"');
  });

  it("flags a DS record at the registry when Cloudflare isn't signing", () => {
    const [f] = run({ zone: zone(), dnssec: "disabled", registry: { ...whois, signed: true } }).findings;
    expect(f!.severity).toBe("urgent");
    expect(run({ zone: zone(), dnssec: "active", registry: { ...whois, signed: true } }).findings).toEqual([]);
  });

  it("reports DNSSEC being turned off", () => {
    const [f] = run({ zone: zone(), dnssec: "disabled" }, { dnssec: "active" }).findings;
    expect([f!.severity, f!.summary]).toEqual(["warning", "example.nz: DNSSEC active → disabled"]);
  });

  it("reports a registrar change and urgent registry statuses", () => {
    const f = run({ zone: zone(), registry: { ...whois, registrar: "Someone Else", statuses: ["serverHold"] } }, { registrar: "Example Registrar Ltd" }).findings;
    expect(f.map((x) => x.severity).sort()).toEqual(["urgent", "warning"]);
  });

  const reg = registrationsFixture.result[0]!;
  it("expiry: quiet far out, warning within 30 days without auto-renew, urgent within 7", () => {
    expect(run({ zone: zone(), registration: reg }).findings).toEqual([]);
    const soon = { ...reg, expires_at: new Date(NOW + 20 * DAY).toISOString() };
    expect(run({ zone: zone(), registration: soon }).findings[0]!.summary).toMatch(/expires in 20 days \(.*, auto-renew OFF\)/);
    expect(run({ zone: zone(), registration: { ...soon, auto_renew: true } }).findings).toEqual([]);
    const [u] = run({ zone: zone(), registration: { ...soon, auto_renew: true, expires_at: new Date(NOW + 3 * DAY).toISOString() } }).findings;
    expect(u!.severity).toBe("urgent");
  });

  it("expiry from RDAP when the domain isn't at Cloudflare Registrar", () => {
    const r: RegistryInfo = { ...parseRdap(rdapFixture as never), expiresAt: new Date(NOW + 10 * DAY).toISOString() };
    expect(run({ zone: zone({ name: "example.net" }), registry: r }).findings[0]!.summary).toContain("auto-renew unknown");
  });

  it("reports auto-renew off and transfer lock removal as changes", () => {
    const f = run({ zone: zone(), registration: { ...reg, auto_renew: false, locked: false } }, { autoRenew: true, locked: true }).findings;
    expect(f.map((x) => x.summary)).toEqual(["example.nz: auto-renew was turned off", "example.nz: transfer lock was removed"]);
  });

  it("does not treat .nz WHOIS (no lock concept) as unlocked", () => {
    expect(run({ zone: zone(), registry: whois }, { locked: true }).snapshot.locked).toBe(true);
  });
});

describe("collector", () => {
  const zones = {
    success: true, errors: [], result: [
      { id: "z1", name: "example.nz", status: "active", name_servers: CF_NS },
      { id: "z2", name: "example.net", status: "active", name_servers: CF_NS },
    ], result_info: { page: 1, per_page: 50, total_pages: 1, count: 2 },
  };
  function ctx(registrar: "ok" | "forbidden", previousState?: DomainsState) {
    const calls: string[] = [];
    const cf = new CloudflareClient("t", 20, async (url) => {
      const u = String(url);
      calls.push(u);
      if (u.includes("/registrar/registrations")) {
        return registrar === "ok" ? jsonResponse(registrationsFixture)
          : jsonResponse({ success: false, errors: [{ code: 10000, message: "Authentication error" }], result: null }, 403);
      }
      if (u.includes("/dnssec")) return jsonResponse({ success: true, errors: [], result: { status: "disabled" } });
      return jsonResponse(zones);
    });
    const c: CollectorContext = { env: testEnv(), config: testConfig({ REGISTRY_LOOKUPS: "true" }), cf, zones: async () => [], now: new Date(NOW), previousState, schedule: "daily", log: () => {} };
    return { c, calls };
  }
  const lookup = async (d: string) => (d.endsWith(".net") ? parseRdap(rdapFixture as never) : whois);
  const bootstrap = async () => jsonResponse({ services: [] });

  it("runs end to end and records state; silent when healthy", async () => {
    const { c, calls } = ctx("ok");
    const r = await createDomainsCollector({ lookup, fetchImpl: bootstrap as never }).collect(c);
    expect(r.findings).toEqual([]);
    expect(calls.filter((u) => u.includes("/dnssec"))).toHaveLength(2);
    expect((r.newState as DomainsState).domains["example.net"]).toEqual({ zoneStatus: "active", dnssec: "disabled", registrar: "Cloudflare, Inc.", autoRenew: false, locked: true });
  });

  it("skips the registrar quietly without permission", async () => {
    const { c } = ctx("forbidden");
    const r = await createDomainsCollector({ lookup, fetchImpl: bootstrap as never }).collect(c);
    expect(r.findings).toEqual([]);
    expect((r.newState as DomainsState).domains["example.net"]!.autoRenew).toBeUndefined();
  });

  it("a failed registry lookup is logged, not fatal", async () => {
    const { c } = ctx("ok");
    const r = await createDomainsCollector({ lookup: async () => { throw new Error("timeout"); }, fetchImpl: bootstrap as never }).collect(c);
    expect(r.stats!["account"]).toEqual({ registryLookupFailures: 2 });
  });
});
