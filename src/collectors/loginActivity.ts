/**
 * Login activity: POSTs to login endpoints (default `/auth/*`, a common
 * login flow path) that Cloudflare let through to the origin.
 *
 * Blocked attempts are already covered by the security-events collector.
 * This one covers the gap where nothing blocks the request, e.g. a leaked
 * hostname being tried from inside a geo-allowed country. Cloudflare can't
 * see whether a login succeeded (many apps answer 200 either way),
 * so this reports *who is trying*, not whether they got in:
 *
 *  - daily:  login POSTs from a country not seen for that hostname before
 *            (learned per hostname, forgotten after 90 days unseen)
 *  - daily:  unusual volume or many distinct IPs for one hostname
 *  - hourly: a burst (urgent only)
 *
 * Dataset (verified against the GraphQL schema and a Free zone, Nov 2026):
 *   httpRequestsAdaptiveGroups   all plans, up to 30 days per query,
 *                                31 days of history. Permission: Zone Analytics Read.
 * The Free plan does NOT expose clientAsn / clientASNDescription on this
 * dataset, so grouping is by country. Client IPs are only counted, never
 * stored or reported. 24h windows on low-traffic hosts are unsampled
 * (sampleInterval 1); the 30-day baseline query is sampled, which is fine
 * for learning countries.
 */
import { chunk, dashLink } from "../cf/zones";
import { globToLike } from "./securityEvents";
import { normalisePath, redactHost } from "../lib/normalise";
import type { Collector, CollectorStats, Finding, ZoneRef } from "../types";

const ZONES_PER_QUERY = 10;
const DAY = 86_400_000;
const BASELINE_DAYS = 30;
const COUNTRY_TTL_DAYS = 90;
const HOURLY_WINDOW_MS = 65 * 60_000;
const LIMIT = 10_000;

export const LOGIN_QUERY = `query AlertflareLogins($zones: [string!], $filter: ZoneHttpRequestsAdaptiveGroupsFilter_InputObject!, $limit: uint64!) {
  viewer { zones(filter: { zoneTag_in: $zones }) {
    zoneTag
    logins: httpRequestsAdaptiveGroups(filter: $filter, limit: $limit, orderBy: [count_DESC]) {
      count dimensions { clientRequestHTTPHost clientRequestPath clientCountryName clientIP }
    }
  } }
}`;

export interface LoginRow {
  zone: string;
  host: string;
  path: string;
  country: string;
  ip: string;
  count: number;
}

interface ZoneLoginData {
  zoneTag: string;
  logins?: {
    count: number;
    dimensions: { clientRequestHTTPHost: string; clientRequestPath: string; clientCountryName: string; clientIP: string };
  }[];
}

export interface LoginState {
  /** host -> country -> last seen (epoch ms) */
  hosts: Record<string, Record<string, number>>;
  learnedAt: number;
}

export interface LoginOptions {
  homeCountries: string[];
  burstThreshold: number;
  distinctIps: number;
  redactHostnames: boolean;
}

export function buildLoginFilter(paths: string[], since: string, until: string) {
  return {
    AND: [
      { datetime_geq: since },
      { datetime_leq: until },
      { clientRequestHTTPMethodName: "POST" },
      // 0 = never reached the origin (blocked/challenged at the edge).
      { originResponseStatus_gt: 0 },
      { OR: paths.map((p) => ({ clientRequestPath_like: globToLike(p) })) },
    ],
  };
}

export function parseLoginZone(zoneName: string, data: ZoneLoginData): LoginRow[] {
  return (data.logins ?? []).map((g) => ({
    zone: zoneName,
    host: (g.dimensions.clientRequestHTTPHost || zoneName).toLowerCase(),
    path: g.dimensions.clientRequestPath || "/",
    country: g.dimensions.clientCountryName || "??",
    ip: g.dimensions.clientIP,
    count: g.count,
  }));
}

interface HostAgg {
  zone: string;
  count: number;
  ips: Set<string>;
  countries: Map<string, { count: number; ips: Set<string> }>;
  paths: Map<string, number>;
}

function aggregateByHost(rows: LoginRow[]): Map<string, HostAgg> {
  const out = new Map<string, HostAgg>();
  for (const r of rows) {
    let h = out.get(r.host);
    if (!h) out.set(r.host, (h = { zone: r.zone, count: 0, ips: new Set(), countries: new Map(), paths: new Map() }));
    h.count += r.count;
    if (r.ip) h.ips.add(r.ip);
    let c = h.countries.get(r.country);
    if (!c) h.countries.set(r.country, (c = { count: 0, ips: new Set() }));
    c.count += r.count;
    if (r.ip) c.ips.add(r.ip);
    const p = normalisePath(r.path);
    h.paths.set(p, (h.paths.get(p) ?? 0) + r.count);
  }
  return out;
}

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

function topPaths(h: HostAgg): string {
  return [...h.paths].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([p, n]) => `${p} ×${n}`).join(", ");
}

function countryList(h: HostAgg): string {
  return [...h.countries].sort((a, b) => b[1].count - a[1].count).slice(0, 5).map(([c, v]) => `${c} ×${v.count}`).join(", ");
}

/** Learn countries per host from rows (no findings). */
export function learn(state: LoginState, rows: LoginRow[], now: number): LoginState {
  const hosts: LoginState["hosts"] = {};
  for (const [host, seen] of Object.entries(state.hosts)) {
    const kept = Object.fromEntries(Object.entries(seen).filter(([, t]) => now - t < COUNTRY_TTL_DAYS * DAY));
    if (Object.keys(kept).length) hosts[host] = kept;
  }
  for (const r of rows) (hosts[r.host] ??= {})[r.country] = now;
  return { hosts, learnedAt: state.learnedAt };
}

/** Daily analysis of the last 24h against the learned baseline. */
export function analyseDaily(rows: LoginRow[], state: LoginState, opts: LoginOptions, date: string): Finding[] {
  const findings: Finding[] = [];
  const home = new Set(opts.homeCountries);
  for (const [host, h] of aggregateByHost(rows)) {
    const shown = opts.redactHostnames ? redactHost(host) : host;
    const known = state.hosts[host] ?? {};
    const link = dashLink(h.zone, "analytics/traffic");
    const base = { source: "login-activity", zone: h.zone, link };

    for (const [country, c] of h.countries) {
      if (country in known || home.has(country.toUpperCase())) continue;
      findings.push({
        ...base,
        fingerprint: `new-country|${host}|${country}|${date}`,
        kind: "event",
        severity: "warning",
        count: c.count,
        summary: `Login attempts on ${shown} from a new country: ${country} (${plural(c.count, "request")}, ${plural(c.ips.size, "IP")})`,
        details: [
          "Reached the origin: nothing at Cloudflare blocked these",
          "Cloudflare can't see whether they succeeded; check the app's own login log",
        ],
      });
    }

    const reasons: string[] = [];
    if (h.count >= opts.burstThreshold) reasons.push(`${h.count} login requests in 24h`);
    if (h.ips.size >= opts.distinctIps) reasons.push(`from ${h.ips.size} different IPs`);
    if (reasons.length) {
      findings.push({
        ...base,
        fingerprint: `volume|${host}`,
        kind: "recurring",
        severity: h.count >= opts.burstThreshold * 3 ? "urgent" : "warning",
        count: h.count,
        summary: `Unusual login activity on ${shown}: ${reasons.join(" ")}`,
        details: [`countries: ${countryList(h)}`, `paths: ${topPaths(h)}`, "Reached the origin: nothing at Cloudflare blocked these"],
      });
    }
  }
  return findings;
}

/** Hourly: urgent bursts only. Shares the daily volume fingerprint. */
export function analyseHourly(rows: LoginRow[], opts: LoginOptions): Finding[] {
  const findings: Finding[] = [];
  for (const [host, h] of aggregateByHost(rows)) {
    if (h.count < opts.burstThreshold) continue;
    const shown = opts.redactHostnames ? redactHost(host) : host;
    findings.push({
      source: "login-activity",
      fingerprint: `volume|${host}`,
      kind: "recurring",
      severity: "urgent",
      zone: h.zone,
      count: h.count,
      summary: `Login burst on ${shown}: ${h.count} login requests in the last hour from ${plural(h.ips.size, "IP")}`,
      details: [`countries: ${countryList(h)}`, `paths: ${topPaths(h)}`, "Reached the origin: nothing at Cloudflare blocked these"],
      link: dashLink(h.zone, "analytics/traffic"),
    });
  }
  return findings;
}

export const loginActivity: Collector = {
  id: "login-activity",
  label: "Login activity",
  schedules: ["daily", "hourly"],
  enabled: (config) => config.loginPaths.length > 0,

  async collect(ctx) {
    const { cf, config, now } = ctx;
    const zones = await ctx.zones();
    const prev = ctx.previousState as LoginState | undefined;
    const opts: LoginOptions = {
      homeCountries: config.loginHomeCountries,
      burstThreshold: config.loginBurstThreshold,
      distinctIps: config.loginDistinctIps,
      redactHostnames: config.redactHostnames,
    };

    const fetchRows = async (sinceMs: number): Promise<LoginRow[]> => {
      const filter = buildLoginFilter(config.loginPaths, new Date(sinceMs).toISOString(), now.toISOString());
      const byId = new Map(zones.map((z) => [z.id, z] as const));
      const rows: LoginRow[] = [];
      for (const batch of chunk(zones, ZONES_PER_QUERY) as ZoneRef[][]) {
        const res = await cf.graphql<{ viewer: { zones: ZoneLoginData[] } }>(LOGIN_QUERY, {
          zones: batch.map((z) => z.id),
          filter,
          limit: LIMIT,
        });
        for (const zd of res.viewer.zones) {
          const z = byId.get(zd.zoneTag);
          if (z) rows.push(...parseLoginZone(z.name, zd));
        }
      }
      return rows;
    };

    if (ctx.schedule === "hourly") {
      // No baseline yet: let the daily run learn first.
      if (!prev) return { findings: [] };
      const rows = await fetchRows(now.getTime() - HOURLY_WINDOW_MS);
      return { findings: analyseHourly(rows, opts), newState: prev };
    }

    if (!prev) {
      // First run: learn the last 30 days silently. The window ends now, so
      // the most recent day is learned too rather than reported.
      const rows = await fetchRows(now.getTime() - BASELINE_DAYS * DAY);
      ctx.log(`learned baseline from ${rows.length} rows`);
      return { findings: [], newState: learn({ hosts: {}, learnedAt: now.getTime() }, rows, now.getTime()) };
    }

    const rows = await fetchRows(now.getTime() - DAY);
    const date = now.toISOString().slice(0, 10);
    const findings = analyseDaily(rows, prev, opts, date);
    const stats: Record<string, CollectorStats> = {};
    for (const h of aggregateByHost(rows).values()) {
      const s = (stats[h.zone] ??= { logins: 0, loginIps: 0 });
      s.logins! += h.count;
      s.loginIps! += h.ips.size;
    }
    return { findings, stats, newState: learn(prev, rows, now.getTime()) };
  },
};
