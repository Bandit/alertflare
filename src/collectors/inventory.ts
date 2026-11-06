/**
 * Zone inventory drift: new/removed DNS hostnames, proxied <-> DNS-only
 * flips, SSL/TLS mode changes, zones added/removed. Diffs against the
 * previous snapshot stored in KV.
 *
 *   GET /zones/{zone_id}/dns_records      Permission: DNS Read
 *   GET /zones/{zone_id}/settings/ssl     Permission: Zone Settings Read
 *
 * Costs 2 subrequests per zone, so zones are processed in rotation: each
 * run handles up to MAX_ZONES_PER_RUN zones (and never dips into the last
 * few subrequests of the shared budget). With many zones each one is
 * checked every few days instead of daily; see README "Limits".
 *
 * Record contents (origin IPs) are deliberately not stored or reported.
 */
import { dashLink } from "../cf/zones";
import type { Collector, CollectorStats, Finding, ZoneRef } from "../types";

interface DnsRecord {
  name: string;
  type: string;
  proxied?: boolean;
  proxiable?: boolean;
}

export interface ZoneSnapshot {
  name: string;
  ssl?: string;
  /** "name|type" -> proxied (true/false); multiple records collapse to "any proxied=false" */
  records: Record<string, boolean>;
}

export interface InventoryState {
  cursor: number;
  /** zone id -> name for every zone seen (independent of rotation) */
  known: Record<string, string>;
  zones: Record<string, ZoneSnapshot>;
}

const RESERVE = 4;
const WEAK_SSL = new Set(["off", "flexible"]);
const PROXY_TYPES = new Set(["A", "AAAA", "CNAME"]);

export function snapshotFrom(name: string, records: DnsRecord[], ssl: string | undefined): ZoneSnapshot {
  const out: Record<string, boolean> = {};
  for (const r of records) {
    const key = `${r.name.toLowerCase()}|${r.type}`;
    const proxied = !!r.proxied;
    // If any record for this name/type is DNS-only, report it as DNS-only.
    out[key] = key in out ? out[key]! && proxied : proxied;
  }
  return { name, ssl, records: out };
}

export function diffSnapshots(prev: ZoneSnapshot, next: ZoneSnapshot, date: string): Finding[] {
  const zone = next.name;
  const f: Finding[] = [];
  const link = dashLink(zone, "dns/records");
  const mk = (fp: string, severity: Finding["severity"], summary: string, details?: string[]): Finding => ({
    source: "inventory",
    fingerprint: `${zone}|${fp}|${date}`,
    kind: "event",
    severity,
    zone,
    summary,
    details,
    link,
  });

  for (const [key, proxied] of Object.entries(next.records)) {
    const [name, type] = key.split("|") as [string, string];
    if (!(key in prev.records)) {
      const exposes = !proxied && PROXY_TYPES.has(type);
      f.push(
        mk(`new|${key}`, exposes ? "warning" : "info", `New DNS record ${name} (${type}, ${proxied ? "proxied" : "DNS only"})`,
          exposes ? ["DNS-only A/AAAA/CNAME exposes the origin address"] : undefined),
      );
    } else if (prev.records[key] !== proxied) {
      f.push(
        proxied
          ? mk(`proxy-on|${key}`, "info", `${name} (${type}) is now proxied`)
          : mk(`proxy-off|${key}`, "warning", `${name} (${type}) switched to DNS only`, ["Origin address is now exposed and bypasses WAF rules"]),
      );
    }
  }
  for (const key of Object.keys(prev.records)) {
    if (!(key in next.records)) {
      const [name, type] = key.split("|") as [string, string];
      f.push(mk(`removed|${key}`, "info", `DNS record removed: ${name} (${type})`));
    }
  }
  if (prev.ssl && next.ssl && prev.ssl !== next.ssl) {
    f.push({
      ...mk(`ssl|${prev.ssl}->${next.ssl}`, WEAK_SSL.has(next.ssl) ? "warning" : "info", `SSL/TLS mode changed: ${prev.ssl} → ${next.ssl}`),
      link: dashLink(zone, "ssl-tls"),
    });
  }
  return f;
}

export function pickRotation<T>(items: T[], cursor: number, n: number): { picked: T[]; nextCursor: number } {
  if (items.length === 0) return { picked: [], nextCursor: 0 };
  const start = cursor % items.length;
  const count = Math.min(n, items.length);
  const picked: T[] = [];
  for (let i = 0; i < count; i++) picked.push(items[(start + i) % items.length]!);
  return { picked, nextCursor: (start + count) % items.length };
}

/** Zones added/removed since last run. Silent on the very first run. */
export function diffZoneSet(known: Record<string, string>, zones: ZoneRef[], date: string): Finding[] {
  if (Object.keys(known).length === 0) return [];
  const findings: Finding[] = [];
  const current = new Set(zones.map((z) => z.id));
  for (const z of zones) {
    if (!(z.id in known)) {
      findings.push({ source: "inventory", fingerprint: `zone-new|${z.name}|${date}`, kind: "event", severity: "info", zone: z.name, summary: `New zone in account: ${z.name}` });
    }
  }
  for (const [id, name] of Object.entries(known)) {
    if (!current.has(id)) {
      findings.push({ source: "inventory", fingerprint: `zone-gone|${name}|${date}`, kind: "event", severity: "warning", zone: name, summary: `Zone no longer active/visible: ${name}` });
    }
  }
  return findings;
}

export const inventory: Collector = {
  id: "inventory",
  label: "Zone inventory",
  schedules: ["daily"],

  async collect(ctx) {
    const { cf, now } = ctx;
    const prev = (ctx.previousState as InventoryState | undefined) ?? { cursor: 0, known: {}, zones: {} };
    const zones = await ctx.zones();
    const date = now.toISOString().slice(0, 10);
    const state: InventoryState = { cursor: prev.cursor, known: {}, zones: { ...prev.zones } };
    const stats: Record<string, CollectorStats> = {};
    const findings = diffZoneSet(prev.known ?? {}, zones, date);
    for (const z of zones) state.known[z.id] = z.name;
    for (const id of Object.keys(state.zones)) if (!(id in state.known)) delete state.zones[id];

    const { picked, nextCursor } = pickRotation(zones, prev.cursor, ctx.config.maxZonesPerRun);
    let processed = 0;
    for (const z of picked as ZoneRef[]) {
      if (cf.remaining < 2 + RESERVE) {
        ctx.log(`budget low: stopping after ${processed} zones`);
        break;
      }
      const records = await cf.getAllPages<DnsRecord>(`/zones/${z.id}/dns_records`, 1000, 2);
      const ssl = await cf.get<{ value: string }>(`/zones/${z.id}/settings/ssl`).then((r) => r.value).catch(() => undefined);
      const snap = snapshotFrom(z.name, records, ssl);
      const old = prev.zones[z.id];
      if (old) findings.push(...diffSnapshots(old, snap, date));
      state.zones[z.id] = snap;
      stats[z.name] = { records: Object.keys(snap.records).length, unproxied: Object.values(snap.records).filter((p) => !p).length };
      processed++;
    }
    state.cursor = processed === picked.length ? nextCursor : (prev.cursor + processed) % Math.max(1, zones.length);
    return { findings, stats, newState: state };
  },
};
