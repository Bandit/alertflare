import { describe, expect, it } from "vitest";
import zonesFixture from "./fixtures/zones.json";
import groupsFixture from "./fixtures/graphql-groups.json";
import auditFixture from "./fixtures/audit-v2.json";
import dnsFixture from "./fixtures/dns-records.json";
import settingsFixture from "./fixtures/zone-settings.json";
import tokensFixture from "./fixtures/user-tokens.json";
import tunnelsFixture from "./fixtures/cfd-tunnels.json";
import { run } from "../src/pipeline";
import { COLLECTORS } from "../src/collectors";
import type { Message, Notifier } from "../src/notify/notifier";
import { jsonResponse, MemoryKV, testEnv } from "./helpers";

class Capture implements Notifier {
  sent: Message[] = [];
  async send(m: Message) { this.sent.push(m); }
}

type Handler = (url: string, init?: RequestInit) => Response;

function fakeApi(overrides: Partial<Record<string, Handler>> = {}) {
  const calls: string[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    calls.push(url);
    const route = (k: string, d: Handler) => (overrides[k] ?? d)(url, init);
    if (url.includes("/graphql")) {
      const body = JSON.parse(String(init?.body));
      if (body.query.includes("AlertflareCaps")) {
        return route("caps", () => jsonResponse({ data: { viewer: { zones: [{ zoneTag: "00000000000000000000000000000001", settings: { firewallEventsAdaptiveGroups: { enabled: true } } }] } } }));
      }
      return route("graphql", () => jsonResponse(groupsFixture));
    }
    if (url.includes("/logs/audit")) return route("audit", () => jsonResponse(auditFixture));
    if (url.includes("/access/logs")) return route("access", () => jsonResponse({ success: false, errors: [{ code: 12006, message: "Access is not enabled" }], result: null }, 403));
    if (url.includes("/dns_records")) return route("dns", () => jsonResponse(dnsFixture));
    if (url.includes("/settings")) return route("settings", () => jsonResponse(settingsFixture));
    if (url.includes("/cfd_tunnel")) return route("tunnels", () => jsonResponse(tunnelsFixture));
    if (url.includes("/user/tokens/verify")) return route("verify", () => jsonResponse({ success: true, errors: [], result: { id: tokensFixture.result[0]!.id, status: "active" } }));
    if (url.includes("/user/tokens")) return route("tokens", () => jsonResponse(tokensFixture));
    if (url.includes("/registrar/")) return route("registrar", () => jsonResponse({ success: false, errors: [{ code: 10000, message: "Authentication error" }], result: null }, 403));
    if (url.includes("/dnssec")) return route("dnssec", () => jsonResponse({ success: true, errors: [], result: { status: "disabled" } }));
    if (url.includes("/zones?")) return route("zones", () => jsonResponse(zonesFixture));
    return jsonResponse({ success: false, errors: [{ code: 7003, message: "no route" }] }, 404);
  };
  return { fetchImpl, calls };
}

// Tuesday 2026-11-10 19:00 UTC (not a heartbeat day)
const NOW = new Date("2026-11-10T19:00:00Z");

describe("pipeline", () => {
  it("daily run: reports interesting findings once, then sends nothing", async () => {
    const env = testEnv();
    const n = new Capture();
    const api = fakeApi();
    const r1 = await run(env, "daily", NOW, { collectors: COLLECTORS, notifier: n, fetchImpl: api.fetchImpl });
    expect(r1.failures).toEqual([]);
    expect(n.sent).toHaveLength(1);
    const text = n.sent[0]!.text;
    expect(n.sent[0]!.subject).toMatch(/Daily digest: 2 urgent, 1 warning, 2 info/);
    expect(text).toContain("dns_records change");
    expect(text.indexOf("URGENT")).toBeLessThan(text.indexOf("WARNING"));
    expect(text).toContain("POST /api/webhook/{id}");
    expect(text).not.toContain("test-token");
    expect(r1.subrequests).toBeLessThanOrEqual(48);

    const n2 = new Capture();
    const r2 = await run(env, "daily", new Date(NOW.getTime() + 86_400_000), { collectors: COLLECTORS, notifier: n2, fetchImpl: api.fetchImpl });
    expect(r2.reported).toEqual([]);
    expect(n2.sent).toEqual([]); // nothing new -> send NOTHING (and not Monday)
  });

  it("isolates a failing collector and rate-limits its failure finding to once a day", async () => {
    const env = testEnv();
    const api = fakeApi({ audit: () => new Response("upstream exploded", { status: 502 }) });
    const n = new Capture();
    const r = await run(env, "daily", NOW, { collectors: COLLECTORS, notifier: n, fetchImpl: api.fetchImpl });
    expect(r.failures).toHaveLength(1);
    expect(r.failures[0]).toContain("audit-logs");
    expect(n.sent[0]!.text).toContain('Collector "Audit logs" failed');
    expect(n.sent[0]!.text).toContain("POST /api/webhook/{id}"); // others still ran
    expect(n.sent[0]!.text).not.toMatch(/at \w+ \(|stack/i);

    const n2 = new Capture();
    await run(env, "hourly", new Date(NOW.getTime() + 3_600_000), { collectors: COLLECTORS, notifier: n2, fetchImpl: api.fetchImpl });
    expect(n2.sent).toEqual([]); // failure already reported today
  });

  it("hourly run sends only urgent items", async () => {
    const env = testEnv();
    const n = new Capture();
    const api = fakeApi();
    await run(env, "hourly", NOW, { collectors: COLLECTORS, notifier: n, fetchImpl: api.fetchImpl });
    expect(n.sent).toHaveLength(1);
    expect(n.sent[0]!.subject).toMatch(/Urgent: 1 urgent \(/);
    expect(api.calls.some((c) => c.includes("graphql"))).toBe(false);
  });

  it("skips Access cleanly when it is not set up", async () => {
    const env = testEnv();
    const r = await run(env, "daily", NOW, { collectors: COLLECTORS, notifier: new Capture(), fetchImpl: fakeApi().fetchImpl });
    expect(r.failures).toEqual([]);
  });

  it("sends a weekly heartbeat even when there is nothing new", async () => {
    const env = testEnv();
    const api = fakeApi();
    await run(env, "daily", NOW, { collectors: COLLECTORS, notifier: new Capture(), fetchImpl: api.fetchImpl });
    const monday = new Date("2026-11-16T19:00:00Z"); // Monday
    const n = new Capture();
    await run(env, "daily", monday, { collectors: COLLECTORS, notifier: n, fetchImpl: api.fetchImpl });
    expect(n.sent).toHaveLength(1);
    expect(n.sent[0]!.subject).toContain("Weekly heartbeat");
    expect(n.sent[0]!.text).toContain("security-events");
    expect(n.sent[0]!.text).toContain("example.test: ");
  });

  it("keeps KV writes low", async () => {
    const env = testEnv();
    const api = fakeApi();
    await run(env, "hourly", NOW, { collectors: COLLECTORS, notifier: new Capture(), fetchImpl: api.fetchImpl });
    const kv = env.ALERTFLARE_STATE as unknown as MemoryKV;
    const before = kv.puts;
    await run(env, "hourly", new Date(NOW.getTime() + 3_600_000), { collectors: COLLECTORS, notifier: new Capture(), fetchImpl: api.fetchImpl });
    expect(kv.puts - before).toBeLessThanOrEqual(2); // ≤ ~48 writes/day from hourly runs
  });
});

describe("delivery failures", () => {
  it("does not mark findings as reported when the send fails", async () => {
    const env = testEnv();
    const api = fakeApi();
    const failing: Notifier = { send: async () => { throw new Error("smtp down"); } };
    await expect(run(env, "daily", NOW, { collectors: COLLECTORS, notifier: failing, fetchImpl: api.fetchImpl })).rejects.toThrow();
    const n = new Capture();
    await run(env, "daily", new Date(NOW.getTime() + 3_600_000), { collectors: COLLECTORS, notifier: n, fetchImpl: api.fetchImpl });
    expect(n.sent[0]!.text).toContain("POST /api/webhook/{id}");
  });

  it("frequent run: tunnels only, silent when healthy, no lastrun write", async () => {
    const env = testEnv();
    const kv = env.ALERTFLARE_STATE as unknown as MemoryKV;
    const api = fakeApi();
    const n = new Capture();
    const r = await run(env, "frequent", new Date("2026-11-10T19:05:00Z"), { collectors: COLLECTORS, notifier: n, fetchImpl: api.fetchImpl });
    expect(r.failures).toEqual([]);
    expect(n.sent).toEqual([]);
    expect(api.calls.every((u) => u.includes("/cfd_tunnel"))).toBe(true);
    expect(kv.store.has("lastrun:frequent")).toBe(false);
    expect(kv.store.has("state:tunnels")).toBe(true);
  });

  it("frequent run: a one-off API error is retried, and failures are reported only after 3 in a row", async () => {
    const env = testEnv();
    const blip = () => jsonResponse({ success: false, errors: [{ code: 10500, message: "Internal authentication error" }], result: null }, 500);
    let calls = 0;
    const once = fakeApi({ tunnels: () => (++calls === 1 ? blip() : jsonResponse(tunnelsFixture)) });
    const r0 = await run(env, "frequent", new Date("2026-11-10T19:00:00Z"), { collectors: COLLECTORS, notifier: new Capture(), fetchImpl: once.fetchImpl });
    expect(r0.failures).toEqual([]); // the retry succeeded

    const down = fakeApi({ tunnels: blip });
    const at = (m: number) => new Date(Date.parse("2026-11-10T19:05:00Z") + m * 60_000);
    const sent: number[] = [];
    for (let i = 0; i < 4; i++) {
      const n = new Capture();
      await run(env, "frequent", at(i * 5), { collectors: COLLECTORS, notifier: n, fetchImpl: down.fetchImpl });
      sent.push(n.sent.length);
      if (i === 0) {
        // A success in between resets the streak.
        await run(env, "frequent", at(2), { collectors: COLLECTORS, notifier: new Capture(), fetchImpl: fakeApi().fetchImpl });
      }
    }
    expect(sent).toEqual([0, 0, 0, 1]);
  });
});
