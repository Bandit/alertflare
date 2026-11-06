/**
 * Security events (WAF custom/managed rules, rate limiting, bot features,
 * etc.) for every zone, last 24h, via the GraphQL Analytics API.
 *
 * Datasets (verified against the GraphQL schema, Nov 2026):
 *  - firewallEventsAdaptiveByTimeGroups  all plans    -> total mitigated count
 *  - firewallEventsAdaptiveGroups        NOT all plans -> server-side aggregation (Pro+)
 *  - firewallEventsAdaptive              all plans    -> raw sampled events (Free fallback,
 *                                                        and Ray ID examples)
 * A zone-scoped query may include at most 10 zones, so zones are batched.
 * Which mode a zone supports is discovered from `settings` and cached in KV
 * for a week so it costs ~1 extra subrequest per week.
 */
import type { Config } from "../config";
import { chunk, dashLink } from "../cf/zones";
import { makeClassifier, type Classifier } from "../lib/classify";
import { normalisePath, redactHost, redactPath } from "../lib/normalise";
import type { Collector, CollectorStats, Finding, ZoneRef } from "../types";

const ZONES_PER_QUERY = 10;
const CAPABILITY_TTL_MS = 7 * 86_400_000;
const GROUPS_LIMIT = 2000;
/** Raw-mode cap per zone. Kept modest for the Free plan's 10ms CPU limit. */
const RAW_LIMIT = 1000;
const EXAMPLES_LIMIT = 50;

/**
 * Actions that are NOT mitigations. Spellings in GraphQL are not documented,
 * so several variants are listed; unknown values are harmless here and are
 * filtered again client-side by isMitigation().
 */
const NON_MITIGATING_ACTIONS = [
  "allow", "log", "bypass", "skip",
  "challenge_solved", "jschallenge_solved", "managed_challenge_solved",
  "managed_challenge_non_interactive_solved", "managed_challenge_interactive_solved",
  "challengesolved", "jschallengesolved", "managedchallengesolved",
  "managedchallengenoninteractivesolved", "managedchallengeinteractivesolved",
  "challenge_bypassed", "jschallenge_bypassed",
];

export function isMitigation(action: string): boolean {
  const a = action.toLowerCase();
  if (/solved|bypass|allow|^log$|^skip$/.test(a)) return false;
  return /block|challenge|connection.?close|drop|deny/.test(a);
}

const SOURCE_LABELS: Record<string, string> = {
  firewallcustom: "Custom rule",
  firewallmanaged: "Managed rule",
  firewallrules: "Firewall rule",
  ratelimit: "Rate limiting",
  ratelimitingrules: "Rate limiting",
  bic: "Browser integrity check",
  hot: "Hotlink protection",
  securitylevel: "Security level",
  uablock: "User agent block",
  zonelockdown: "Zone lockdown",
  waf: "WAF",
  botfight: "Bot fight mode",
  botmanagement: "Bot management",
  l7ddos: "HTTP DDoS",
  validation: "Validation",
  asn: "IP access rule (ASN)",
  country: "IP access rule (country)",
  ip: "IP access rule",
  iprange: "IP access rule",
  apishield: "API Shield",
  apishieldschemavalidation: "API Shield schema",
  dlp: "Data loss prevention",
  sanitycheck: "Sanity check",
  firewallforai: "Firewall for AI",
};

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source.toLowerCase()] ?? source;
}

/** One aggregated row, independent of which dataset it came from. */
export interface EventRow {
  zone: string;
  host: string;
  action: string;
  source: string;
  ruleId: string;
  description: string;
  method: string;
  path: string;
  asn: string;
  asnName: string;
  country: string;
  count: number;
  rayId?: string;
}

// ---------- GraphQL ----------

const SETTINGS_QUERY = `query AlertflareCaps($zones: [string!]) {
  viewer { zones(filter: { zoneTag_in: $zones }) {
    zoneTag
    settings { firewallEventsAdaptiveGroups { enabled } firewallEventsAdaptive { enabled } }
  } }
}`;

const GROUP_DIMENSIONS = `action source ruleId description clientRequestHTTPHost clientRequestPath
  clientRequestHTTPMethodName clientAsn clientASNDescription clientCountryName`;

const RAW_FIELDS = `action source ruleId description clientRequestHTTPHost clientRequestPath
  clientRequestHTTPMethodName clientAsn clientASNDescription clientCountryName rayName sampleInterval`;

export const GROUPS_QUERY = `query AlertflareGroups($zones: [string!], $total: ZoneFirewallEventsAdaptiveByTimeGroupsFilter_InputObject!, $groups: ZoneFirewallEventsAdaptiveGroupsFilter_InputObject!, $examples: ZoneFirewallEventsAdaptiveFilter_InputObject!, $limit: uint64!, $exLimit: uint64!) {
  viewer { zones(filter: { zoneTag_in: $zones }) {
    zoneTag
    total: firewallEventsAdaptiveByTimeGroups(filter: $total, limit: 1) { count }
    groups: firewallEventsAdaptiveGroups(filter: $groups, limit: $limit, orderBy: [count_DESC]) {
      count dimensions { ${GROUP_DIMENSIONS} }
    }
    examples: firewallEventsAdaptive(filter: $examples, limit: $exLimit, orderBy: [datetime_DESC]) {
      rayName clientRequestHTTPHost clientRequestPath clientRequestHTTPMethodName clientAsn source ruleId
    }
  } }
}`;

export const RAW_QUERY = `query AlertflareRaw($zones: [string!], $total: ZoneFirewallEventsAdaptiveByTimeGroupsFilter_InputObject!, $events: ZoneFirewallEventsAdaptiveFilter_InputObject!, $limit: uint64!) {
  viewer { zones(filter: { zoneTag_in: $zones }) {
    zoneTag
    total: firewallEventsAdaptiveByTimeGroups(filter: $total, limit: 1) { count }
    events: firewallEventsAdaptive(filter: $events, limit: $limit, orderBy: [datetime_DESC]) { ${RAW_FIELDS} }
  } }
}`;

/** `*`/`?` glob -> SQL LIKE pattern used by GraphQL `_like`/`_notlike`. */
export function globToLike(glob: string): string {
  return glob.replace(/\*/g, "%").replace(/\?/g, "_");
}

export function buildFilters(config: Config, since: string, until: string) {
  const base = [
    { datetime_geq: since },
    { datetime_leq: until },
    { action_notin: NON_MITIGATING_ACTIONS },
  ];
  // Drop ignore-list paths server-side to save rows (LIKE is case-sensitive,
  // so mixed-case scanner paths are still caught client-side).
  const noNoise = config.ignorePaths.map((g) => ({ clientRequestPath_notlike: globToLike(g) }));
  const interesting = {
    OR: [
      ...config.interestingPaths.map((g) => ({ clientRequestPath_like: globToLike(g) })),
      { clientRequestHTTPMethodName_in: config.interestingMethods },
    ],
  };
  return {
    total: { AND: base },
    filtered: { AND: [...base, ...noNoise] },
    examples: { AND: [...base, ...noNoise, interesting] },
  };
}

// ---------- response shapes ----------

interface GroupDims {
  action: string;
  source: string;
  ruleId: string;
  description: string;
  clientRequestHTTPHost: string;
  clientRequestPath: string;
  clientRequestHTTPMethodName: string;
  clientAsn: string;
  clientASNDescription: string;
  clientCountryName: string;
}

interface RawEvent extends GroupDims {
  rayName: string;
  sampleInterval?: number;
}

export interface ZoneGroupsData {
  zoneTag: string;
  total?: { count: number }[];
  groups?: { count: number; dimensions: GroupDims }[];
  examples?: Pick<RawEvent, "rayName" | "clientRequestHTTPHost" | "clientRequestPath" | "clientRequestHTTPMethodName" | "clientAsn" | "source" | "ruleId">[];
}

export interface ZoneRawData {
  zoneTag: string;
  total?: { count: number }[];
  events?: RawEvent[];
}

function rowFrom(zone: string, d: GroupDims, count: number, rayId?: string): EventRow {
  return {
    zone,
    host: d.clientRequestHTTPHost || zone,
    action: d.action,
    source: d.source,
    ruleId: d.ruleId,
    description: d.description,
    method: (d.clientRequestHTTPMethodName || "GET").toUpperCase(),
    path: d.clientRequestPath || "/",
    asn: String(d.clientAsn ?? ""),
    asnName: d.clientASNDescription ?? "",
    country: d.clientCountryName ?? "",
    count,
    rayId,
  };
}

export function parseGroupsZone(zoneName: string, data: ZoneGroupsData): { rows: EventRow[]; total: number; truncated: boolean } {
  const groups = data.groups ?? [];
  const rows = groups.filter((g) => isMitigation(g.dimensions.action)).map((g) => rowFrom(zoneName, g.dimensions, g.count));
  // Attach example Ray IDs to rows with the same fingerprint.
  for (const ex of data.examples ?? []) {
    const key = fpKey(rowFrom(zoneName, { ...ex, action: "", description: "", clientASNDescription: "", clientCountryName: "" } as GroupDims, 0));
    const target = rows.find((r) => !r.rayId && fpKey(r) === key);
    if (target) target.rayId = ex.rayName;
  }
  return { rows, total: data.total?.[0]?.count ?? 0, truncated: groups.length >= GROUPS_LIMIT };
}

export function parseRawZone(zoneName: string, data: ZoneRawData): { rows: EventRow[]; total: number; truncated: boolean } {
  const events = data.events ?? [];
  const rows = events
    .filter((e) => isMitigation(e.action))
    .map((e) => rowFrom(zoneName, e, Math.max(1, e.sampleInterval ?? 1), e.rayName));
  return { rows, total: data.total?.[0]?.count ?? 0, truncated: events.length >= RAW_LIMIT };
}

// ---------- aggregation + classification ----------

function fpKey(r: Pick<EventRow, "zone" | "host" | "source" | "ruleId" | "method" | "path" | "asn">): string {
  return [r.zone, r.host.toLowerCase(), `${r.source}:${r.ruleId}`, r.method, normalisePath(r.path), r.asn].join("|");
}

interface Agg {
  rows: EventRow[];
  count: number;
  countries: Set<string>;
  rayId?: string;
}

export function aggregate(
  rows: EventRow[],
  classifier: Classifier,
  opts: { redactHostnames?: boolean } = {},
): { findings: Finding[]; stats: Record<string, CollectorStats> } {
  const stats: Record<string, CollectorStats> = {};
  const byFp = new Map<string, Agg>();
  for (const r of rows) {
    const k = fpKey(r);
    let a = byFp.get(k);
    if (!a) byFp.set(k, (a = { rows: [], count: 0, countries: new Set() }));
    a.rows.push(r);
    a.count += r.count;
    if (r.country) a.countries.add(r.country);
    if (!a.rayId && r.rayId) a.rayId = r.rayId;
  }

  const findings: Finding[] = [];
  for (const [fp, a] of byFp) {
    const r = a.rows[0]!;
    const zs = (stats[r.zone] ??= { mitigated: 0, noise: 0, boring: 0, interesting: 0 });
    zs.mitigated! += a.count;
    const verdict = classifier.classify({ path: r.path, method: r.method, count: a.count, source: r.source });
    if (verdict.kind === "noise") {
      zs.noise! += a.count;
      continue;
    }
    if (verdict.kind === "boring") {
      zs.boring! += a.count;
      continue;
    }
    zs.interesting! += a.count;
    const rule = r.description ? `${sourceLabel(r.source)} "${r.description}"` : sourceLabel(r.source);
    const actions = [...new Set(a.rows.map((x) => x.action))].join("/");
    const asn = r.asn ? `AS${r.asn}${r.asnName ? ` ${r.asnName}` : ""}` : "unknown ASN";
    const countries = [...a.countries].slice(0, 3).join(", ");
    findings.push({
      source: "security-events",
      fingerprint: fp,
      severity: verdict.severity,
      zone: r.zone,
      count: a.count,
      kind: "recurring",
      summary: `${r.method} ${normalisePath(r.path)} on ${opts.redactHostnames ? redactHost(r.host) : r.host}: ${actions} by ${rule}`,
      details: [
        `from ${asn}${countries ? ` (${countries})` : ""}`,
        `e.g. ${redactPath(r.path)}`,
        `why: ${verdict.reasons.join(", ")}`,
      ],
      rayId: a.rayId,
      link: dashLink(r.zone, "security/analytics/events"),
    });
  }
  return { findings, stats };
}

// ---------- collector ----------

interface CapsState {
  checkedAt: number;
  groups: Record<string, boolean>;
}

export const securityEvents: Collector = {
  id: "security-events",
  label: "Security events",
  schedules: ["daily"],

  async collect(ctx) {
    const { cf, config, now } = ctx;
    const classifier = makeClassifier(config);
    const zones = await ctx.zones();
    const until = now.toISOString();
    const since = new Date(now.getTime() - 86_400_000).toISOString();
    const filters = buildFilters(config, since, until);

    // Capability discovery (cached for a week).
    let caps = ctx.previousState as CapsState | undefined;
    const stale = !caps || now.getTime() - caps.checkedAt > CAPABILITY_TTL_MS || zones.some((z) => !(z.id in caps!.groups));
    if (stale) {
      caps = { checkedAt: now.getTime(), groups: {} };
      for (const batch of chunk(zones, ZONES_PER_QUERY)) {
        const res = await cf.graphql<{ viewer: { zones: { zoneTag: string; settings?: { firewallEventsAdaptiveGroups?: { enabled: boolean } } }[] } }>(
          SETTINGS_QUERY,
          { zones: batch.map((z) => z.id) },
        );
        for (const z of res.viewer.zones) caps.groups[z.zoneTag] = !!z.settings?.firewallEventsAdaptiveGroups?.enabled;
      }
    }

    const byId = new Map(zones.map((z) => [z.id, z] as const));
    const groupsZones = zones.filter((z) => caps!.groups[z.id]);
    const rawZones = zones.filter((z) => !caps!.groups[z.id]);

    const allRows: EventRow[] = [];
    const perZone: Record<string, CollectorStats> = {};
    const record = (zone: ZoneRef, parsed: { rows: EventRow[]; total: number; truncated: boolean }) => {
      allRows.push(...parsed.rows);
      perZone[zone.name] = { total: parsed.total, truncated: parsed.truncated ? 1 : 0 };
    };

    for (const batch of chunk(groupsZones, ZONES_PER_QUERY)) {
      const res = await cf.graphql<{ viewer: { zones: ZoneGroupsData[] } }>(GROUPS_QUERY, {
        zones: batch.map((z) => z.id),
        total: filters.total,
        groups: filters.filtered,
        examples: filters.examples,
        limit: GROUPS_LIMIT,
        exLimit: EXAMPLES_LIMIT,
      });
      for (const zd of res.viewer.zones) {
        const z = byId.get(zd.zoneTag);
        if (z) record(z, parseGroupsZone(z.name, zd));
      }
    }
    for (const batch of chunk(rawZones, ZONES_PER_QUERY)) {
      const res = await cf.graphql<{ viewer: { zones: ZoneRawData[] } }>(RAW_QUERY, {
        zones: batch.map((z) => z.id),
        total: filters.total,
        events: filters.filtered,
        limit: RAW_LIMIT,
      });
      for (const zd of res.viewer.zones) {
        const z = byId.get(zd.zoneTag);
        if (z) record(z, parseRawZone(z.name, zd));
      }
    }

    const { findings, stats } = aggregate(allRows, classifier, { redactHostnames: config.redactHostnames });
    // Per-zone breakdown for the heartbeat.
    for (const zone of Object.keys(perZone)) {
      const s = stats[zone] ?? { boring: 0, interesting: 0 };
      const t = perZone[zone]!;
      // `total` includes server-side-dropped scanner noise.
      t.noise = Math.max(0, t.total! - s.boring! - s.interesting!);
      t.interesting = s.interesting!;
    }
    return { findings, stats: perZone, newState: caps };
  },
};
