/**
 * Account audit logs (v2, GA since 2026-03-10, all plans, 18-month retention).
 *   GET /accounts/{account_id}/logs/audit?since&before&limit&direction&cursor
 *   Permission: Account Settings Read
 *
 * Daily: every non-"view" action in the last 25h is reported once.
 * Hourly: only urgent items (API tokens, members, logins from new IPs,
 *         failed logins) from the last 2h. Both schedules share one
 *         "already reported" store, so nothing is sent twice.
 *
 * Request/response bodies (resource.request / resource.response) are never
 * read into notifications: they can contain secrets such as a new token value.
 */
import { dashLink } from "../cf/zones";
import { redactText, truncateToken } from "../lib/normalise";
import type { Collector, CollectorStats, Finding, Severity } from "../types";

export interface AuditEntry {
  id: string;
  account?: { id?: string; name?: string };
  action?: { description?: string; result?: string; time?: string; type?: string };
  actor?: {
    id?: string;
    context?: string;
    email?: string;
    ip_address?: string;
    token_id?: string;
    token_name?: string;
    type?: string;
  };
  raw?: { cf_ray_id?: string; method?: string; status_code?: number; uri?: string; user_agent?: string };
  resource?: { id?: string; product?: string; scope?: unknown; type?: string };
  zone?: { id?: string; name?: string };
}

export interface AuditState {
  /** actor (email or id) -> known login IPs */
  loginIps: Record<string, string[]>;
  /** end of the last daily window (ISO), so daily windows never overlap */
  dailyUntil?: string;
}

/**
 * Data-plane activity that the audit log records as "create"/"update" but
 * which is not a configuration change. Override with AUDIT_IGNORE / extend
 * with AUDIT_EXTRA_IGNORE.
 *
 * Plain entries: case-insensitive substring match on action.description.
 * Entries containing "/": prefix match on "<resource.product>/<resource.type>",
 * for actions whose descriptions are too generic to match safely.
 */
export const DEFAULT_AUDIT_IGNORE = [
  "Query D1 Database",
  "Execute an Analytics Engine SQL query",
  "Upload Object",
  "Upload Worker Assets",
  "Create Worker Assets Upload Session",
  // Payment intents are created for every purchase (e.g. a domain transfer).
  // Payment *method* changes are still reported.
  "Create Payment Intent",
  // Browsing Workers Logs in the dashboard: "Run a query", "List keys", … (POSTs).
  "workers/observability.",
  // Vector data operations (insert/upsert/delete by id); index create/delete are kept.
  "vectorize/indexes.",
];

/**
 * Actor types whose entries are side effects of an action already logged
 * for a user (DNS records created by Email Routing, certificate renewals,
 * Wrangler asset uploads). Include them with AUDIT_INCLUDE_SYSTEM=true.
 */
const SYSTEM_ACTORS = new Set(["system", "delegated_service"]);

const MAX_IPS_PER_ACTOR = 30;

type Category = "token" | "member" | "login" | "security" | "dns" | "tunnel" | "access" | "other";

export function categorise(e: AuditEntry): Category {
  const hay = [e.resource?.type, e.resource?.product, e.action?.description, e.raw?.uri]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (/\b(login|log in|sign.?in|sso_login|logout)\b|sso_login/.test(hay)) return "login";
  if (/token/.test(hay)) return "token";
  if (/member|invite|\brole|membership|user_group|account_user/.test(hay)) return "member";
  if (/access|zero.?trust|identity.?provider|\bidp\b/.test(hay)) return "access";
  if (/tunnel|cfd_tunnel|cloudflared/.test(hay)) return "tunnel";
  if (/firewall|waf|ruleset|rule|rate.?limit|security|bot|page.?shield|ip.?access/.test(hay)) return "security";
  if (/dns/.test(hay)) return "dns";
  return "other";
}

function actorLabel(e: AuditEntry): string {
  const a = e.actor ?? {};
  if (a.email) return a.email;
  if (a.token_name) return `token "${a.token_name}"`;
  if (a.token_id) return `token ${truncateToken(a.token_id)}`;
  return a.type ?? "unknown actor";
}

export interface Classified {
  severity: Severity;
  category: Category;
  /** null = do not report (e.g. login from a known IP) */
  report: boolean;
  newIp?: boolean;
}

export function classifyEntry(e: AuditEntry, state: AuditState, seeding: boolean): Classified {
  const category = categorise(e);
  const failed = (e.action?.result ?? "").toLowerCase() === "failure";
  if (category === "login") {
    const who = e.actor?.email ?? e.actor?.id ?? "?";
    const ip = e.actor?.ip_address ?? "";
    const known = state.loginIps[who] ?? [];
    const newIp = !!ip && !known.includes(ip);
    if (failed) return { severity: "urgent", category, report: true, newIp };
    if (newIp && !seeding) return { severity: "urgent", category, report: true, newIp };
    return { severity: "info", category, report: false, newIp };
  }
  if (category === "token" || category === "member") return { severity: "urgent", category, report: true };
  if (category === "security" || category === "access" || category === "tunnel") {
    return { severity: "warning", category, report: true };
  }
  return { severity: failed ? "warning" : "info", category, report: true };
}

export function fnv1a(s: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16);
}

/** Keep readable ids ("http_request_firewall_custom"), truncate random ones. */
export function shortId(id: string): string {
  if (/\d/.test(id) && id.length > 8) return truncateToken(id);
  return id.length > 40 ? truncateToken(id, 40) : id;
}

function describe(e: AuditEntry): string {
  return e.action?.description || [e.resource?.product, e.resource?.type].filter(Boolean).join(" ") || "resource";
}

export function entryToFinding(e: AuditEntry, c: Classified, timezone: string): Finding {
  const verb = e.action?.type ?? "change";
  const what = describe(e);
  const resId = e.resource?.id ? ` ${shortId(String(e.resource.id))}` : "";
  const when = e.action?.time
    ? new Intl.DateTimeFormat("en-GB", { timeZone: timezone, dateStyle: "short", timeStyle: "short" }).format(new Date(e.action.time))
    : "";
  const result = (e.action?.result ?? "").toLowerCase() === "failure" ? " (FAILED)" : "";
  const summary =
    c.category === "login"
      ? `${c.newIp ? "Login from NEW IP" : "Login"}${result}: ${actorLabel(e)}`
      : `${actorLabel(e)} ${verb}: ${what}${resId}${result}`;
  const details = [
    [when, e.actor?.ip_address ? `from ${e.actor.ip_address}` : "", e.actor?.context ? `via ${e.actor.context}` : ""]
      .filter(Boolean)
      .join(" "),
  ].filter(Boolean);
  return {
    source: "audit-logs",
    fingerprint: e.id,
    kind: "event",
    severity: c.severity,
    zone: e.zone?.name || "account",
    summary: redactText(summary),
    details: details.map(redactText),
    rayId: e.raw?.cf_ray_id || undefined,
    link: dashLink(undefined, "audit-log"),
  };
}

export interface ProcessOptions {
  urgentOnly: boolean;
  timezone: string;
  ignore?: string[];
  includeSystem?: boolean;
  /** Used to date info rollups; defaults to the latest entry time. */
  now?: Date;
}

export function isIgnored(e: AuditEntry, ignore: string[], includeSystem: boolean): boolean {
  if (!includeSystem && SYSTEM_ACTORS.has((e.actor?.type ?? "").toLowerCase())) return true;
  const d = (e.action?.description ?? "").toLowerCase();
  const r = `${e.resource?.product ?? ""}/${e.resource?.type ?? ""}`.toLowerCase();
  return ignore.some((i) => {
    const needle = i.toLowerCase();
    return needle.includes("/") ? r.startsWith(needle) : d.includes(needle);
  });
}

export function processEntries(
  entries: AuditEntry[],
  prev: AuditState | undefined,
  opts: ProcessOptions,
): { findings: Finding[]; state: AuditState; stats: CollectorStats } {
  const seeding = !prev;
  const state: AuditState = { ...prev, loginIps: { ...(prev?.loginIps ?? {}) } };
  const stats: CollectorStats = { changes: 0, logins: 0, urgent: 0, ignored: 0 };
  const findings: Finding[] = [];
  const ignore = opts.ignore ?? DEFAULT_AUDIT_IGNORE;
  /** info-level entries, rolled up per zone/actor/product */
  const rollups = new Map<string, { zone: string; actor: string; product: string; counts: Map<string, number>; ids: string[] }>();
  // Oldest first so "new IP" is judged in order.
  const sorted = [...entries].sort((a, b) => (a.action?.time ?? "").localeCompare(b.action?.time ?? ""));
  for (const e of sorted) {
    if ((e.action?.type ?? "").toLowerCase() === "view") continue;
    if (isIgnored(e, ignore, !!opts.includeSystem)) {
      stats.ignored!++;
      continue;
    }
    const c = classifyEntry(e, state, seeding);
    if (c.category === "login") {
      stats.logins!++;
      const who = e.actor?.email ?? e.actor?.id ?? "?";
      const ip = e.actor?.ip_address;
      if (ip && (e.action?.result ?? "").toLowerCase() !== "failure") {
        const ips = (state.loginIps[who] ?? []).filter((x) => x !== ip);
        ips.push(ip);
        state.loginIps[who] = ips.slice(-MAX_IPS_PER_ACTOR);
      }
    } else {
      stats.changes!++;
    }
    if (!c.report) continue;
    if (c.severity === "urgent") stats.urgent!++;
    if (opts.urgentOnly && c.severity !== "urgent") continue;
    if (c.severity === "info") {
      const zone = e.zone?.name || "account";
      const actor = actorLabel(e);
      const product = e.resource?.product || "other";
      const key = `${zone}|${actor}|${product}`;
      let r = rollups.get(key);
      if (!r) rollups.set(key, (r = { zone, actor, product, counts: new Map(), ids: [] }));
      r.ids.push(e.id);
      const what = describe(e) + ((e.action?.result ?? "").toLowerCase() === "failure" ? " (FAILED)" : "");
      r.counts.set(what, (r.counts.get(what) ?? 0) + 1);
      continue;
    }
    findings.push(entryToFinding(e, c, opts.timezone));
  }

  for (const [key, r] of rollups) {
    const total = [...r.counts.values()].reduce((a, b) => a + b, 0);
    const parts = [...r.counts.entries()].sort((a, b) => b[1] - a[1]).map(([d, n]) => (n > 1 ? `${d} ×${n}` : d));
    findings.push({
      source: "audit-logs",
      // Keyed on the entries themselves: re-fetching the same entries can
      // never produce a second report.
      fingerprint: `rollup|${key}|${fnv1a(r.ids.sort().join(","))}`,
      kind: "event",
      severity: "info",
      zone: r.zone,
      summary: redactText(`${r.actor}: ${total} ${r.product} change${total === 1 ? "" : "s"}`),
      details: [redactText(parts.slice(0, 6).join(", ") + (parts.length > 6 ? `, +${parts.length - 6} more` : ""))],
      link: dashLink(undefined, "audit-log"),
    });
  }
  return { findings, state, stats };
}

export const auditLogs: Collector = {
  id: "audit-logs",
  label: "Audit logs",
  schedules: ["daily", "hourly"],

  async collect(ctx) {
    const hourly = ctx.schedule === "hourly";
    const prev = ctx.previousState as AuditState | undefined;
    // Daily: continue from the end of the previous daily window (max 3 days
    // back), so rollup counts never double-count. Hourly: last 2h; urgent
    // items are deduped by entry id.
    const floor = ctx.now.getTime() - (hourly ? 2 : 72) * 3_600_000;
    const fromPrev = !hourly && prev?.dailyUntil ? Date.parse(prev.dailyUntil) : NaN;
    const sinceMs = Number.isFinite(fromPrev) ? Math.max(fromPrev, floor) : ctx.now.getTime() - (hourly ? 2 : 24) * 3_600_000;
    const since = new Date(sinceMs).toISOString();
    const before = ctx.now.toISOString();
    const base = `/accounts/${ctx.env.CF_ACCOUNT_ID}/logs/audit?since=${encodeURIComponent(since)}&before=${encodeURIComponent(before)}&limit=1000&direction=desc`;

    const entries: AuditEntry[] = [];
    let cursor: string | undefined;
    const maxPages = hourly ? 1 : 3;
    for (let page = 0; page < maxPages; page++) {
      const env = await ctx.cf.getEnvelope<AuditEntry[]>(cursor ? `${base}&cursor=${encodeURIComponent(cursor)}` : base);
      entries.push(...(env.result ?? []));
      cursor = env.result_info?.cursor;
      if (!cursor || (env.result ?? []).length === 0) break;
    }

    const { findings, state, stats } = processEntries(entries, prev, {
      urgentOnly: hourly,
      timezone: ctx.config.timezone,
      ignore: ctx.config.auditIgnore,
      includeSystem: ctx.config.auditIncludeSystem,
      now: ctx.now,
    });
    if (!hourly) state.dailyUntil = before;
    return { findings, newState: state, stats: hourly ? undefined : { account: stats } };
  },
};
