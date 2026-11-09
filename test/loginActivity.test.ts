import { describe, expect, it } from "vitest";
import fixture from "./fixtures/graphql-logins.json";
import {
  analyseDaily, analyseHourly, buildLoginFilter, learn, loginActivity, parseLoginZone,
  type LoginOptions, type LoginRow, type LoginState,
} from "../src/collectors/loginActivity";
import { CloudflareClient } from "../src/cf/client";
import type { CollectorContext } from "../src/types";
import { jsonResponse, testConfig, testEnv } from "./helpers";

const HOST = "app-k3x9qw7vbn2mzp4rt8y.example.com";
const NOW = Date.parse("2026-11-10T19:00:00Z");
const DAY = 86_400_000;
const opts: LoginOptions = { homeCountries: [], burstThreshold: 30, distinctIps: 10, redactHostnames: true };
const rows = parseLoginZone("example.com", fixture.data.viewer.zones[0]!);
const baseline: LoginState = { hosts: { [HOST]: { GB: NOW - DAY } }, learnedAt: NOW - 10 * DAY };

describe("buildLoginFilter", () => {
  it("only counts POSTs that reached the origin, on the watched paths", () => {
    const f = buildLoginFilter(["/auth/*", "/login"], "a", "b");
    expect(f.AND).toContainEqual({ clientRequestHTTPMethodName: "POST" });
    expect(f.AND).toContainEqual({ originResponseStatus_gt: 0 });
    expect(f.AND).toContainEqual({ OR: [{ clientRequestPath_like: "/auth/%" }, { clientRequestPath_like: "/login" }] });
  });
});

describe("analyseDaily", () => {
  it("is silent for countries already seen on that host", () => {
    expect(analyseDaily(rows.filter((r) => r.country === "GB"), baseline, opts, "2026-11-10")).toEqual([]);
  });

  it("warns about a new country, with counts and no IPs or full hostname", () => {
    const f = analyseDaily(rows, baseline, opts, "2026-11-10");
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("warning");
    expect(f[0]!.kind).toBe("event");
    expect(f[0]!.summary).toBe("Login attempts on app-k3x9….example.com from a new country: FR (13 requests, 2 IPs)");
    const text = JSON.stringify({ ...f[0], fingerprint: "" });
    expect(text).not.toContain("198.51.100");
    expect(text).not.toContain(HOST);
  });

  it("treats LOGIN_HOME_COUNTRIES as always known", () => {
    expect(analyseDaily(rows, baseline, { ...opts, homeCountries: ["FR"] }, "2026-11-10")).toEqual([]);
  });

  const burst: LoginRow[] = Array.from({ length: 12 }, (_, i) => ({
    zone: "example.com", host: HOST, path: `/auth/login_flow/${"ab12".repeat(8)}`, country: "GB", ip: `192.0.2.${i}`, count: 5,
  }));

  it("flags volume and many IPs even from a known country", () => {
    const f = analyseDaily(burst, baseline, opts, "2026-11-10");
    expect(f).toHaveLength(1);
    expect(f[0]!.fingerprint).toBe(`volume|${HOST}`);
    expect(f[0]!.severity).toBe("warning");
    expect(f[0]!.summary).toBe("Unusual login activity on app-k3x9….example.com: 60 login requests in 24h from 12 different IPs");
    expect(f[0]!.details).toContain("paths: /auth/login_flow/{id} ×60");
  });

  it("is urgent at 3× the burst threshold", () => {
    const f = analyseDaily(burst.map((r) => ({ ...r, count: 10 })), baseline, opts, "2026-11-10");
    expect(f[0]!.severity).toBe("urgent");
  });
});

describe("analyseHourly", () => {
  it("only reports bursts, as urgent, sharing the daily fingerprint", () => {
    expect(analyseHourly(rows, opts)).toEqual([]);
    const f = analyseHourly(rows, { ...opts, burstThreshold: 15 });
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe("urgent");
    expect(f[0]!.fingerprint).toBe(`volume|${HOST}`);
    expect(f[0]!.summary).toBe("Login burst on app-k3x9….example.com: 18 login requests in the last hour from 3 IPs");
  });
});

describe("learn", () => {
  it("adds countries and forgets ones unseen for 90 days", () => {
    const old: LoginState = { hosts: { [HOST]: { GB: NOW - DAY, US: NOW - 91 * DAY }, "gone.example.com": { GB: NOW - 100 * DAY } }, learnedAt: 0 };
    const next = learn(old, rows, NOW);
    expect(Object.keys(next.hosts)).toEqual([HOST]);
    expect(Object.keys(next.hosts[HOST]!).sort()).toEqual(["FR", "GB"]);
  });
});

describe("collector", () => {
  const zones = [{ id: "00000000000000000000000000000001", name: "example.com" }];
  function ctx(schedule: "daily" | "hourly", previousState: unknown) {
    const bodies: { filter: { AND: { datetime_geq?: string }[] } }[] = [];
    const cf = new CloudflareClient("t", 10, async (_u, init) => {
      bodies.push(JSON.parse(String(init!.body)).variables);
      return jsonResponse(fixture);
    });
    const c: CollectorContext = {
      env: testEnv(), config: testConfig(), cf, zones: async () => zones, now: new Date(NOW),
      previousState, schedule, log: () => {},
    };
    return { c, bodies };
  }
  const since = (b: { filter: { AND: { datetime_geq?: string }[] } }) => b.filter.AND.find((x) => x.datetime_geq)!.datetime_geq;

  it("first daily run learns 30 days silently", async () => {
    const { c, bodies } = ctx("daily", undefined);
    const r = await loginActivity.collect(c);
    expect(r.findings).toEqual([]);
    expect(since(bodies[0]!)).toBe(new Date(NOW - 30 * DAY).toISOString());
    expect((r.newState as LoginState).hosts[HOST]).toBeDefined();
  });

  it("hourly does nothing until a baseline exists", async () => {
    const { c, bodies } = ctx("hourly", undefined);
    expect((await loginActivity.collect(c)).findings).toEqual([]);
    expect(bodies).toHaveLength(0);
  });

  it("later daily runs look at 24h and report the new country", async () => {
    const { c, bodies } = ctx("daily", baseline);
    const r = await loginActivity.collect(c);
    expect(since(bodies[0]!)).toBe(new Date(NOW - DAY).toISOString());
    expect(r.findings.map((f) => f.fingerprint)).toEqual([`new-country|${HOST}|FR|2026-11-10`]);
    expect(r.stats).toEqual({ "example.com": { logins: 18, loginIps: 3 } });
  });
});
