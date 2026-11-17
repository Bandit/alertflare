import { describe, expect, it } from "vitest";
import fixture from "./fixtures/cfd-tunnels.json";
import { pollTunnels, summariseEvents, tunnels, tunnelSummary, type ApiTunnel, type TunnelsState } from "../src/collectors/tunnels";
import { CloudflareClient } from "../src/cf/client";
import type { CollectorContext } from "../src/types";
import { jsonResponse, MemoryKV, testConfig, testEnv } from "./helpers";

const T = (hhmm: string) => Date.parse(`2026-11-18T${hhmm}:00Z`);
const iso = (hhmm: string) => new Date(T(hhmm)).toISOString();
const tun = (status: string, inactive?: string, id = "a", name = "app-tunnel", active?: string): ApiTunnel => ({
  id, name, status, conns_inactive_at: inactive ? iso(inactive) : null, conns_active_at: active ? iso(active) : null,
});
const opts = (hhmm: string) => ({ now: T(hhmm), graceMinutes: 5 });

describe("pollTunnels", () => {
  it("first poll is silent and skips never-run tunnels", () => {
    const { findings, state } = pollTunnels(undefined, fixture.result as ApiTunnel[], opts("10:00"));
    expect(findings).toEqual([]);
    expect(Object.keys(state.tunnels)).toEqual(["11111111-1111-4111-8111-111111111111"]);
    expect(state.events).toEqual([]);
  });

  it("alerts once when down past the grace period, then once on recovery", () => {
    let s = pollTunnels(undefined, [tun("healthy")], opts("00:00")).state;
    let r = pollTunnels(s, [tun("down", "00:03")], opts("00:05")); // down 2 min: no alert yet
    expect(r.findings).toEqual([]);
    r = pollTunnels(r.state, [tun("down", "00:03")], opts("00:10")); // 7 min
    expect(r.findings.map((f) => [f.severity, f.summary])).toEqual([["urgent", "Tunnel app-tunnel is down (for 7 min)"]]);
    r = pollTunnels(r.state, [tun("down", "00:03")], opts("00:15")); // still down: no repeat
    expect(r.findings).toEqual([]);
    // As observed live: on reconnect conns_inactive_at clears and conns_active_at moves.
    r = pollTunnels(r.state, [tun("healthy", undefined, "a", "app-tunnel", "00:19")], opts("00:20"));
    expect(r.findings.map((f) => [f.severity, f.summary])).toEqual([["info", "Tunnel app-tunnel recovered (healthy) after about 17 min"]]);
    expect(r.state.events).toMatchObject([{ kind: "drop", at: iso("00:03"), alerted: true, upAt: iso("00:19") }]);
    s = r.state;
    expect(pollTunnels(s, [tun("healthy", undefined, "a", "app-tunnel", "00:19")], opts("00:25")).findings).toEqual([]);
  });

  it("replays a flapping storm: no emails, but it's remembered for the digest", () => {
    // Both tunnels flap between 00:12 and 00:22 (the native alert sent 12 emails).
    // Live semantics: healthy => conns_inactive_at null; reconnect moves conns_active_at.
    const polls: [string, ApiTunnel[]][] = [
      ["00:10", [tun("healthy", undefined, "c", "cubi", "23:00"), tun("healthy", undefined, "h", "ha", "23:00")]],
      // cubi dropped 00:12 and was back 00:13, between polls; ha degraded
      ["00:15", [tun("healthy", undefined, "c", "cubi", "00:13"), tun("degraded", undefined, "h", "ha", "23:00")]],
      // cubi down since 00:20; ha dropped 00:19 and was back 00:20
      ["00:20", [tun("down", "00:20", "c", "cubi", "00:13"), tun("healthy", undefined, "h", "ha", "00:20")]],
      ["00:25", [tun("healthy", undefined, "c", "cubi", "00:22"), tun("healthy", undefined, "h", "ha", "00:20")]],
    ];
    let state: TunnelsState | undefined;
    const sent = [];
    for (const [at, list] of polls) {
      const r = pollTunnels(state, list, opts(at));
      sent.push(...r.findings);
      state = r.state;
    }
    expect(sent).toEqual([]);
    const summary = summariseEvents(state!.events, T("00:00"), T("01:00"), "2026-11-18");
    expect(summary.map((f) => [f.severity, f.summary, f.details])).toEqual([
      ["info", "Tunnel cubi went down 2× since the last digest", ["longest outage about 2 min", "each recovered before the alert grace period"]],
      ["info", "Tunnel ha went down 1×, degraded 1× since the last digest", ["each recovered before the alert grace period"]],
    ]);
  });

  it("ignores conns_active_at on the first sight of a tunnel (no false drop)", () => {
    const a = pollTunnels({ tunnels: { a: { name: "app-tunnel", status: "healthy" } }, events: [] }, [tun("healthy", undefined, "a", "app-tunnel", "09:00")], opts("10:00"));
    expect(a.state.events).toEqual([]);
  });

  it("falls back to first-seen time when the API gives no conns_inactive_at", () => {
    let r = pollTunnels({ tunnels: { a: { name: "app-tunnel", status: "healthy" } }, events: [] }, [tun("down")], opts("00:00"));
    expect(r.findings).toEqual([]);
    r = pollTunnels(r.state, [tun("down")], opts("00:06"));
    expect(r.findings[0]!.summary).toBe("Tunnel app-tunnel is down (for 6 min)");
  });

  it("only changes state when something changes (KV write budget)", () => {
    const a = pollTunnels(undefined, [tun("healthy", "23:00")], opts("00:00")).state;
    const b = pollTunnels(a, [tun("healthy", "23:00")], opts("00:05")).state;
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
  });
});

describe("summariseEvents", () => {
  it("warns at 3+ drops or after an alert, and respects the window", () => {
    const ev = (at: string, extra = {}) => ({ id: "a", name: "app-tunnel", kind: "drop" as const, at: iso(at), ...extra });
    expect(summariseEvents([ev("01:00"), ev("02:00"), ev("03:00")], T("00:00"), T("04:00"), "d")[0]!.severity).toBe("warning");
    expect(summariseEvents([ev("01:00", { alerted: true })], T("00:00"), T("04:00"), "d")[0]!.details).toEqual(["1 outage long enough to alert"]);
    expect(summariseEvents([ev("01:00")], T("01:00"), T("04:00"), "d")).toEqual([]);
  });
});

describe("collectors", () => {
  const ctx = (cf: CloudflareClient, previousState: unknown, env = testEnv(), schedule: "frequent" | "daily" = "frequent") =>
    ({ env, config: testConfig(), cf, zones: async () => [], now: new Date(T("10:00")), previousState, schedule, log: () => {} }) as CollectorContext;

  it("tunnels: reads the API and keeps state", async () => {
    const cf = new CloudflareClient("t", 5, async () => jsonResponse(fixture));
    const r = await tunnels.collect(ctx(cf, undefined));
    expect(Object.keys((r.newState as TunnelsState).tunnels)).toHaveLength(1);
  });

  it("tunnels: an empty list after seeing tunnels is a failure, not calm (missing permission)", async () => {
    const cf = new CloudflareClient("t", 5, async () => jsonResponse({ ...fixture, result: [] }));
    const prev = { tunnels: { a: { name: "x", status: "healthy" } }, events: [] };
    await expect(tunnels.collect(ctx(cf, prev))).rejects.toThrow(/may have lost Cloudflare Tunnel Read/);
  });

  it("tunnel-summary: reads state:tunnels without writing it", async () => {
    const env = testEnv();
    const kv = env.ALERTFLARE_STATE as unknown as MemoryKV;
    kv.store.set("state:tunnels", JSON.stringify({ tunnels: {}, events: [{ id: "a", name: "app-tunnel", kind: "drop", at: iso("09:00") }] }));
    const r = await tunnelSummary.collect(ctx(new CloudflareClient("t", 1), { summarisedUntil: iso("08:00") }, env, "daily"));
    expect(r.findings.map((f) => f.summary)).toEqual(["Tunnel app-tunnel went down 1× since the last digest"]);
    expect(r.newState).toEqual({ summarisedUntil: iso("10:00") });
    expect(kv.puts).toBe(0);
  });
});
