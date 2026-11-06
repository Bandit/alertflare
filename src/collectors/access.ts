/**
 * Zero Trust Access: denied/failed authentications, last 24h.
 *   GET /accounts/{account_id}/access/logs/access_requests?since&until&limit&direction
 *   Permission: Access: Audit Logs Read
 *
 * NOTE: on the Zero Trust Free plan Access logs are retained for only 24h,
 * so this must run at least daily (it does) and gaps of >24h lose data.
 *
 * If Access/Zero Trust has never been set up on the account, the API returns
 * an error rather than an empty list; that case is detected and the
 * collector skips cleanly. A genuine permission error is still reported.
 */
import { CloudflareApiError } from "../cf/client";
import { dashLink } from "../cf/zones";
import type { Collector, CollectorStats, Finding } from "../types";

export interface AccessRequest {
  action?: string;
  allowed?: boolean;
  app_domain?: string;
  app_uid?: string;
  connection?: string;
  created_at?: string;
  ip_address?: string;
  ray_id?: string;
  user_email?: string;
  /** Not in the documented API schema; used if present. */
  country?: string;
  country_code?: string;
}

/** Repeated denials at or above this count are raised to "warning". */
const WARN_COUNT = 10;

export function isNotSetUp(err: unknown): boolean {
  if (!(err instanceof CloudflareApiError)) return false;
  // 10000 = authentication/permission error: a real problem, not "not set up".
  if (err.codes.includes(10000)) return false;
  if (err.status === 404) return true;
  return /not\s+(enabled|found|set ?up|configured)|no\s+(access\s+)?organi[sz]ation|zero trust.*(disabled|not)/i.test(err.message);
}

export function processAccessRequests(rows: AccessRequest[]): { findings: Finding[]; stats: CollectorStats } {
  const stats: CollectorStats = { requests: rows.length, denied: 0 };
  const groups = new Map<string, { app: string; who: string; country: string; count: number; ips: Set<string>; ray?: string; idp?: string }>();
  for (const r of rows) {
    if (r.allowed !== false) continue;
    stats.denied!++;
    const app = r.app_domain || r.app_uid || "unknown app";
    const who = r.user_email || "(no identity)";
    const country = (r.country_code || r.country || "").toUpperCase();
    const key = `${app}|${who.toLowerCase()}|${country}`;
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { app, who, country, count: 0, ips: new Set(), idp: r.connection }));
    g.count++;
    if (r.ip_address) g.ips.add(r.ip_address);
    if (!g.ray && r.ray_id) g.ray = r.ray_id;
  }
  const findings: Finding[] = [];
  for (const [key, g] of groups) {
    const ips = [...g.ips];
    findings.push({
      source: "access",
      fingerprint: key,
      kind: "recurring",
      severity: g.count >= WARN_COUNT ? "warning" : "info",
      zone: "account",
      count: g.count,
      summary: `Access denied: ${g.who} → ${g.app}${g.country ? ` (${g.country})` : ""}`,
      details: [
        `${ips.length} IP${ips.length === 1 ? "" : "s"}: ${ips.slice(0, 3).join(", ")}${ips.length > 3 ? ", …" : ""}${g.idp ? ` · IdP ${g.idp}` : ""}`,
      ],
      rayId: g.ray,
      link: dashLink(undefined, "one/insights/logs/access"),
    });
  }
  return { findings, stats };
}

export const access: Collector = {
  id: "access",
  label: "Zero Trust Access",
  schedules: ["daily"],

  async collect(ctx) {
    const until = ctx.now.toISOString();
    const since = new Date(ctx.now.getTime() - 86_400_000).toISOString();
    let rows: AccessRequest[];
    try {
      rows = await ctx.cf.get<AccessRequest[]>(
        `/accounts/${ctx.env.CF_ACCOUNT_ID}/access/logs/access_requests?since=${encodeURIComponent(since)}&until=${encodeURIComponent(until)}&limit=1000&direction=desc`,
      );
    } catch (err) {
      if (isNotSetUp(err)) {
        ctx.log("Access not set up on this account: skipping");
        return { findings: [], stats: { account: { notSetUp: 1 } } };
      }
      throw err;
    }
    const { findings, stats } = processAccessRequests(rows ?? []);
    return { findings, stats: { account: stats } };
  },
};
