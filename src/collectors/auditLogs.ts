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
}

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

export function entryToFinding(e: AuditEntry, c: Classified, timezone: string): Finding {
  const verb = e.action?.type ?? "change";
  const what = e.action?.description || [e.resource?.product, e.resource?.type].filter(Boolean).join(" ") || "resource";
  const resId = e.resource?.id ? ` ${truncateToken(String(e.resource.id))}` : "";
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

export function processEntries(
  entries: AuditEntry[],
  prev: AuditState | undefined,
  opts: { urgentOnly: boolean; timezone: string },
): { findings: Finding[]; state: AuditState; stats: CollectorStats } {
  const seeding = !prev;
  const state: AuditState = { loginIps: { ...(prev?.loginIps ?? {}) } };
  const stats: CollectorStats = { changes: 0, logins: 0, urgent: 0 };
  const findings: Finding[] = [];
  // Oldest first so "new IP" is judged in order.
  const sorted = [...entries].sort((a, b) => (a.action?.time ?? "").localeCompare(b.action?.time ?? ""));
  for (const e of sorted) {
    if ((e.action?.type ?? "").toLowerCase() === "view") continue;
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
    findings.push(entryToFinding(e, c, opts.timezone));
  }
  return { findings, state, stats };
}

export const auditLogs: Collector = {
  id: "audit-logs",
  label: "Audit logs",
  schedules: ["daily", "hourly"],

  async collect(ctx) {
    const hourly = ctx.schedule === "hourly";
    const windowMs = (hourly ? 2 : 25) * 3_600_000;
    const since = new Date(ctx.now.getTime() - windowMs).toISOString();
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

    const { findings, state, stats } = processEntries(entries, ctx.previousState as AuditState | undefined, {
      urgentOnly: hourly,
      timezone: ctx.config.timezone,
    });
    return { findings, newState: state, stats: hourly ? undefined : { account: stats } };
  },
};
