import { describe, expect, it } from "vitest";
import fixture from "./fixtures/dns-records.json";
import { diffSnapshots, diffZoneSet, pickRotation, snapshotFrom } from "../src/collectors/inventory";

const base = snapshotFrom("example.test", fixture.result, "full");

describe("inventory snapshots", () => {
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
