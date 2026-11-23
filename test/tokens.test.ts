import { describe, expect, it } from "vitest";
import fixture from "./fixtures/user-tokens.json";
import { describeScope, diffTokens, snapshotToken, tokens, type ApiToken, type TokensState } from "../src/collectors/tokens";
import { CloudflareClient } from "../src/cf/client";
import type { CollectorContext } from "../src/types";
import { jsonResponse, testConfig, testEnv } from "./helpers";

const NOW = Date.parse("2026-11-10T19:00:00Z");
const DAY = 86_400_000;
const list = fixture.result as ApiToken[];
const SELF = list[0]!.id;
const opts = { now: NOW, date: "2026-11-10", selfId: SELF };
const base = diffTokens(undefined, list, opts).state;
const clone = (): ApiToken[] => JSON.parse(JSON.stringify(list));

describe("snapshots", () => {
  it("describe scope without IDs", () => {
    expect(describeScope({ "com.cloudflare.api.account.zone.*": "*" })).toBe("all zones");
    expect(describeScope({ "com.cloudflare.api.account.zone.abc": "*", "com.cloudflare.api.account.zone.def": "*" })).toBe("2 zones");
    expect(describeScope({ "com.cloudflare.api.account.abc": { "com.cloudflare.api.account.zone.*": "*" } })).toBe("all zones");
    expect(describeScope({ "com.cloudflare.api.account.abc": "*" })).toBe("account");
    expect(describeScope({ "com.cloudflare.api.user.abc": "*" })).toBe("user");
  });

  it("never stores IDs or IP ranges in readable form", () => {
    const s = JSON.stringify(snapshotToken(list[1]!));
    expect(s).not.toContain("0000000000000000000000000000");
    expect(s).not.toContain("192.0.2");
    expect(snapshotToken(list[1]!).perms).toEqual(["allow DNS Write @ 1 zone"]);
  });
});

describe("diffTokens", () => {
  it("first run is silent", () => {
    expect(diffTokens(undefined, list, opts).findings).toEqual([]);
  });

  it("no change, no findings", () => {
    expect(diffTokens(base, list, opts).findings).toEqual([]);
  });

  it("new token is urgent and lists its permissions", () => {
    const t = clone();
    t.push({ ...t[1]!, id: "0000000000000000000000000000cccc", name: "totally legit", condition: undefined });
    const [f] = diffTokens(base, t, opts).findings;
    expect(f!.severity).toBe("urgent");
    expect(f!.summary).toBe('New API token created: "totally legit"');
    expect(f!.details).toEqual(["allow DNS Write @ 1 zone", "no IP restriction", "If you didn't create it, delete it and change your Cloudflare password"]);
  });

  it("alertflare's own token gaining write access is urgent", () => {
    const t = clone();
    t[0]!.policies![0]!.permission_groups.push({ id: "x", name: "DNS Write" });
    const [f] = diffTokens(base, t, opts).findings;
    expect(f!.severity).toBe("urgent");
    expect(f!.summary).toBe(`API token "monitor-readonly" (alertflare's own token) permissions changed: it gained write access`);
    expect(f!.details).toEqual(["+ allow DNS Write @ all zones"]);
  });

  it("adding a read permission is a warning; scope-only changes are noticed", () => {
    const t = clone();
    t[0]!.policies![1]!.permission_groups.push({ id: "y", name: "Registrar: Domains Read" });
    expect(diffTokens(base, t, opts).findings[0]!.severity).toBe("warning");
    const z = clone();
    z[1]!.policies![0]!.resources = { "com.cloudflare.api.account.zone.00000000000000000000000000000002": "*" };
    expect(diffTokens(base, z, opts).findings[0]!.details).toEqual(["same permissions, different zones/accounts"]);
  });

  it("IP restriction removed, token disabled, renamed, deleted", () => {
    const t = clone();
    delete t[1]!.condition;
    t[1]!.status = "disabled";
    t[1]!.name = "renamed";
    const summaries = diffTokens(base, t, opts).findings.map((f) => `${f.severity}: ${f.summary}`);
    expect(summaries).toEqual([
      'warning: API token "renamed" IP restriction removed',
      'warning: API token "renamed" is now disabled (was active)',
      'info: API token "Edit zone DNS" renamed to "renamed"',
    ]);
    const [d] = diffTokens(base, [list[1]!], opts).findings;
    expect([d!.severity, d!.summary]).toEqual(["urgent", `API token "monitor-readonly" (alertflare's own token) was deleted`]);
  });

  it("warns before expiry", () => {
    const t = clone();
    t[1]!.expires_on = new Date(NOW + 5 * DAY).toISOString();
    expect(diffTokens(base, t, opts).findings.map((f) => f.summary)).toContain('API token "Edit zone DNS" expires in 5 days');
  });
});

describe("collector", () => {
  function ctx(schedule: "daily" | "hourly", previousState: unknown, status = 200, body: unknown = fixture) {
    const cf = new CloudflareClient("t", 10, async (url) =>
      String(url).includes("/verify") ? jsonResponse({ success: true, errors: [], result: { id: SELF, status: "active" } }) : jsonResponse(body, status));
    return { env: testEnv(), config: testConfig(), cf, zones: async () => [], now: new Date(NOW), previousState, schedule, log: () => {} } as CollectorContext;
  }

  it("skips quietly without permission", async () => {
    const r = await tokens.collect(ctx("daily", undefined, 403, { success: false, errors: [{ code: 9109, message: "Unauthorized" }], result: null }));
    expect(r).toEqual({ findings: [] });
  });

  it("learns its own token id on the first run", async () => {
    const r = await tokens.collect(ctx("daily", undefined));
    expect((r.newState as TokensState).self).toBe(SELF);
  });

  it("hourly reports urgent changes only, and holds back the rest for the digest", async () => {
    const prev = { ...base, tokens: { ...base.tokens } };
    prev.tokens[list[1]!.id] = { ...prev.tokens[list[1]!.id]!, name: "old name" };
    const r = await tokens.collect(ctx("hourly", prev));
    expect(r.findings).toEqual([]);
    expect(r.newState).toBe(prev);
  });
});
