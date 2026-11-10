import { describe, expect, it } from "vitest";
import fixture from "./fixtures/dns-records.json";
import { diffSnapshots, diffZoneSet, pickRotation, pickSettings, snapshotFrom } from "../src/collectors/inventory";
import settingsFixture from "./fixtures/zone-settings.json";

const base = snapshotFrom("example.test", fixture.result, "full");

describe("inventory snapshots", () => {
  it("records tunnel hostnames, not tunnel ids", () => {
    expect(base.tunnels).toEqual(["app.example.test"]);
    expect(JSON.stringify(base)).not.toContain("tunnel-id");
  });
  it("stores name/type -> proxied, never record contents", () => {
    expect(base.records).toEqual({
      "example.test|A": true,
      "app.example.test|CNAME": true,
      "mail.example.test|MX": false,
      "nas.example.test|A": false,
    });
    expect(JSON.stringify(base)).not.toContain("192.0.2");
  });
});

describe("diffSnapshots", () => {
  it("is silent when nothing changed", () => {
    expect(diffSnapshots(base, base, "2026-11-06")).toEqual([]);
  });
  it("reports new hostnames, proxy flips, removals and SSL changes", () => {
    const records = fixture.result.map((r) => (r.name === "app.example.test" ? { ...r, proxied: false } : r)).filter((r) => r.name !== "mail.example.test");
    records.push({ id: "r9", name: "new.example.test", type: "AAAA", content: "2001:db8::1", proxiable: true, proxied: false, ttl: 1 });
    const next = snapshotFrom("example.test", records, "flexible");
    const out = diffSnapshots(base, next, "2026-11-06");
    const by = (s: string) => out.find((f) => f.summary.includes(s));
    expect(by("new.example.test")).toMatchObject({ severity: "warning" });
    expect(by("app.example.test (CNAME) switched to DNS only")).toMatchObject({ severity: "warning" });
    expect(by("removed: mail.example.test")).toMatchObject({ severity: "info" });
    expect(by("SSL/TLS mode changed: full → flexible")).toMatchObject({ severity: "warning" });
    expect(out).toHaveLength(4);
  });
});

describe("tunnel hostname reminders", () => {
  const tunnel = (name: string) => ({ id: name, name, type: "CNAME", content: "aaaabbbb-cccc-dddd-eeee-ffff00001111.cfargotunnel.com", proxiable: true, proxied: true, ttl: 1 });

  it("reminds you to check WAF rules cover a new tunnel hostname", () => {
    const next = snapshotFrom("example.test", [...fixture.result, tunnel("photos.example.test")], "full");
    const out = diffSnapshots(base, next, "2026-11-10");
    expect(out).toHaveLength(1); // replaces the generic "New DNS record" line
    expect(out[0]).toMatchObject({
      severity: "warning",
      summary: "New tunnel hostname photos.example.test: check your WAF rules cover it",
      link: "https://dash.cloudflare.com/?to=/:account/example.test/security/security-rules",
    });
  });

  it("catches an existing hostname being re-pointed at a tunnel", () => {
    const records = fixture.result.map((r) => (r.name === "example.test" ? r : r)).concat([{ id: "w", name: "www.example.test", type: "CNAME", content: "example.test", proxiable: true, proxied: true, ttl: 1 }]);
    const before = snapshotFrom("example.test", records, "full");
    const after = snapshotFrom("example.test", records.map((r) => (r.name === "www.example.test" ? tunnel("www.example.test") : r)), "full");
    expect(diffSnapshots(before, after, "d").map((f) => f.summary)).toEqual(["New tunnel hostname www.example.test: check your WAF rules cover it"]);
  });

  it("redacts random-looking tunnel hostnames", () => {
    const next = snapshotFrom("example.test", [...fixture.result, tunnel("photos-k3x9qw7vbn2mzp4rt8y.example.test")], "full");
    expect(diffSnapshots(base, next, "d")[0]!.summary).toContain("photos-k…");
  });

  it("does not alert for existing tunnels when upgrading from an older snapshot", () => {
    const { tunnels: _, ...legacy } = base;
    expect(diffSnapshots(legacy, base, "d")).toEqual([]);
    // ...but a genuinely new tunnel record is still caught
    const next = snapshotFrom("example.test", [...fixture.result, tunnel("new.example.test")], "full");
    expect(diffSnapshots(legacy, next, "d").map((f) => f.summary)).toEqual(["New tunnel hostname new.example.test: check your WAF rules cover it"]);
  });
});

describe("diffZoneSet", () => {
  it("is silent on first run, then reports added/removed zones", () => {
    const zones = [{ id: "1", name: "a.test" }];
    expect(diffZoneSet({}, zones, "d")).toEqual([]);
    const out = diffZoneSet({ "2": "b.test" }, zones, "d");
    expect(out.map((f) => f.summary)).toEqual(["New zone in account: a.test", "Zone no longer active/visible: b.test"]);
  });
});

describe("pickRotation", () => {
  it("rotates through zones across runs", () => {
    const zs = [1, 2, 3, 4, 5];
    const a = pickRotation(zs, 0, 2);
    expect(a).toEqual({ picked: [1, 2], nextCursor: 2 });
    const b = pickRotation(zs, 4, 2);
    expect(b).toEqual({ picked: [5, 1], nextCursor: 1 });
    expect(pickRotation(zs, 0, 10).picked).toEqual(zs);
  });
});

describe("edge certificate settings", () => {
  const good = pickSettings(settingsFixture.result);
  const snap = (o: object) => snapshotFrom("example.test", fixture.result, { ...good, ...o });
  const diff = (a: object, b: object) => diffSnapshots(snap(a), snap(b), "2026-11-10");

  it("reads ssl, min TLS, HSTS and Always Use HTTPS from GET /settings", () => {
    expect(good).toEqual({ ssl: "strict", minTls: "1.2", hsts: { enabled: true, maxAge: 2592000 }, alwaysHttps: true });
  });

  it("is silent when nothing changed", () => {
    expect(diff({}, {})).toEqual([]);
  });

  it("warns when min TLS is lowered, info when raised", () => {
    const [down] = diff({}, { minTls: "1.0" });
    expect(down!.severity).toBe("warning");
    expect(down!.summary).toBe("Minimum TLS version lowered: 1.2 → 1.0");
    expect(down!.link).toContain("ssl-tls/edge-certificates");
    const [up] = diff({ minTls: "1.0" }, {});
    expect(up!.severity).toBe("info");
  });

  it("warns when HSTS or Always Use HTTPS is turned off", () => {
    expect(diff({}, { hsts: { enabled: false, maxAge: 0 } }).map((f) => [f.severity, f.summary])).toEqual([["warning", "HSTS was turned off"]]);
    expect(diff({}, { alwaysHttps: false }).map((f) => f.severity)).toEqual(["warning"]);
    expect(diff({ hsts: { enabled: false, maxAge: 0 } }, {})[0]!.summary).toBe("HSTS turned on (max-age 30 days)");
    expect(diff({}, { hsts: { enabled: true, maxAge: 15552000 } })[0]!.summary).toBe("HSTS max-age changed: 30 days → 180 days");
  });

  it("does not alert when upgrading from a snapshot without these fields", () => {
    const old = snapshotFrom("example.test", fixture.result, "strict");
    expect(diffSnapshots(old, snap({ minTls: "1.0", alwaysHttps: false }), "2026-11-10")).toEqual([]);
  });
});
