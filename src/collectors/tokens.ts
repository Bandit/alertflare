/**
 * API token inventory: your *user* API tokens' metadata (never their
 * values; Cloudflare only returns a value once, at creation).
 *
 *   GET /user/tokens          Permission: User > API Tokens > Read
 *   GET /user/tokens/verify   (no permission needed) identifies alertflare's own token
 *
 * User-owned tokens belong to your login, not the account, so creating,
 * editing or deleting them is NOT in the account audit log, and (checked
 * on a live account, Nov 2026) not in the user audit log either. This
 * collector snapshots the token list and reports differences:
 *
 *   new token                                urgent
 *   permissions / scope changed              urgent if it gained write access, else warning
 *   IP restriction removed or changed        warning
 *   token deleted, disabled or renamed       warning / info
 *   expiring within 14 days                  warning
 *
 * Runs daily and hourly (a surprise new token is the main sign of a
 * compromised login). The first run only takes a snapshot. Without the
 * permission (403) the collector skips quietly.
 */
import { CloudflareApiError } from "../cf/client";
import { fnv1a } from "./auditLogs";
import type { Collector, Finding } from "../types";

const DAY = 86_400_000;
const EXPIRY_WARN_DAYS = 14;

export interface ApiToken {
  id: string;
  name: string;
  status: string;
  expires_on?: string | null;
  not_before?: string | null;
  modified_on?: string;
  policies?: {
    effect: string;
    resources: Record<string, unknown>;
    permission_groups: { id: string; name: string }[];
  }[];
  condition?: { request_ip?: { in?: string[]; not_in?: string[] } };
}

export interface TokenSnapshot {
  name: string;
  status: string;
  expires?: string;
  /** "allow DNS Write @ all zones", sorted. No IDs. */
  perms: string[];
  /** Hash of the exact policy resources (contains IDs, so only hashed). */
  scopeHash: string;
  /** Hash of IP conditions; undefined = no IP restriction. */
  ipHash?: string;
}

export interface TokensState {
  tokens: Record<string, TokenSnapshot>;
  self?: string;
}

/** Describe a policy's resources without IDs. */
export function describeScope(resources: Record<string, unknown>): string {
  const parts = new Set<string>();
  let zones = 0;
  const walk = (res: Record<string, unknown>) => {
    for (const [key, value] of Object.entries(res)) {
      if (/\.zone\.\*$/.test(key)) parts.add("all zones");
      else if (/\.zone\./.test(key)) zones++;
      else if (/\.account\.\*$/.test(key)) parts.add("all accounts");
      else if (/\.account\./.test(key)) {
        if (value && typeof value === "object") walk(value as Record<string, unknown>);
        else parts.add("account");
      } else if (/\.user\./.test(key)) parts.add("user");
      else parts.add("other");
    }
  };
  walk(resources);
  if (zones) parts.add(`${zones} zone${zones === 1 ? "" : "s"}`);
  return [...parts].sort().join(", ") || "nothing";
}

export function snapshotToken(t: ApiToken): TokenSnapshot {
  const perms = (t.policies ?? [])
    .flatMap((p) => p.permission_groups.map((g) => `${p.effect} ${g.name} @ ${describeScope(p.resources)}`))
    .sort();
  const ip = t.condition?.request_ip;
  const ipList = ip ? [...(ip.in ?? []).map((c) => `in:${c}`), ...(ip.not_in ?? []).map((c) => `out:${c}`)].sort() : [];
  return {
    name: t.name,
    status: t.status,
    expires: t.expires_on ?? undefined,
    perms: [...new Set(perms)],
    scopeHash: fnv1a(JSON.stringify((t.policies ?? []).map((p) => [p.effect, p.resources, p.permission_groups.map((g) => g.id).sort()]))),
    ipHash: ipList.length ? fnv1a(ipList.join(",")) : undefined,
  };
}

const isWrite = (perm: string) => perm.startsWith("allow ") && /\b(write|edit|admin)\b/i.test(perm);

function summarisePerms(perms: string[], max = 6): string[] {
  return perms.length <= max ? perms : [...perms.slice(0, max), `… and ${perms.length - max} more`];
}

export function diffTokens(
  prev: TokensState | undefined,
  tokens: ApiToken[],
  opts: { now: number; date: string; selfId?: string },
): { findings: Finding[]; state: TokensState } {
  const next: TokensState = { tokens: {}, self: opts.selfId ?? prev?.self };
  for (const t of tokens) next.tokens[t.id] = snapshotToken(t);
  const findings: Finding[] = [];
  const link = "https://dash.cloudflare.com/profile/api-tokens";
  const add = (fp: string, severity: Finding["severity"], summary: string, details?: string[], kind: Finding["kind"] = "event") =>
    findings.push({ source: "tokens", fingerprint: fp, severity, summary, details, zone: "account", link, kind });
  const label = (id: string, s: TokenSnapshot) => `"${s.name}"${id === next.self ? " (alertflare's own token)" : ""}`;

  if (prev) {
    for (const [id, s] of Object.entries(next.tokens)) {
      const old = prev.tokens[id];
      const who = label(id, s);
      if (!old) {
        add(`new|${id}`, "urgent", `New API token created: ${who}`, [
          ...summarisePerms(s.perms),
          s.ipHash ? "IP-restricted" : "no IP restriction",
          "If you didn't create it, delete it and change your Cloudflare password",
        ]);
        continue;
      }
      if (old.scopeHash !== s.scopeHash || old.perms.join("\n") !== s.perms.join("\n")) {
        const gained = s.perms.filter((p) => !old.perms.includes(p));
        const lost = old.perms.filter((p) => !s.perms.includes(p));
        const writeGained = gained.some(isWrite);
        add(`perms|${id}|${s.scopeHash}`, writeGained ? "urgent" : "warning", `API token ${who} permissions changed${writeGained ? ": it gained write access" : ""}`, [
          ...gained.map((p) => `+ ${p}`),
          ...lost.map((p) => `- ${p}`),
          ...(gained.length + lost.length === 0 ? ["same permissions, different zones/accounts"] : []),
        ]);
      }
      if (old.ipHash !== s.ipHash) {
        add(`ip|${id}|${s.ipHash ?? "none"}`, "warning", s.ipHash ? `API token ${who} IP restriction changed` : `API token ${who} IP restriction removed`);
      }
      if (old.status !== s.status) {
        add(`status|${id}|${s.status}|${opts.date}`, s.status === "active" ? "info" : "warning", `API token ${who} is now ${s.status} (was ${old.status})`);
      }
      if (old.name !== s.name) add(`rename|${id}|${s.name}`, "info", `API token "${old.name}" renamed to ${who}`);
    }
    for (const [id, old] of Object.entries(prev.tokens)) {
      if (!(id in next.tokens)) add(`deleted|${id}`, id === next.self ? "urgent" : "warning", `API token ${label(id, old)} was deleted`);
    }
  }

  for (const [id, s] of Object.entries(next.tokens)) {
    if (!s.expires || s.status !== "active") continue;
    const days = Math.floor((Date.parse(s.expires) - opts.now) / DAY);
    if (days <= EXPIRY_WARN_DAYS) {
      add(`expiry|${id}|${s.expires}`, id === next.self ? "urgent" : "warning",
        days < 0 ? `API token ${label(id, s)} expired` : `API token ${label(id, s)} expires in ${days} day${days === 1 ? "" : "s"}`,
        id === next.self ? ["alertflare will stop working when it expires"] : undefined, "recurring");
    }
  }
  return { findings, state: next };
}

export const tokens: Collector = {
  id: "tokens",
  label: "API tokens",
  schedules: ["daily", "hourly"],

  async collect(ctx) {
    const { cf, now } = ctx;
    const prev = ctx.previousState as TokensState | undefined;
    let list: ApiToken[];
    try {
      list = await cf.getAllPages<ApiToken>("/user/tokens", 50, 4);
    } catch (err) {
      if (err instanceof CloudflareApiError && [401, 403].includes(err.status)) {
        ctx.log("no permission (add User > API Tokens > Read to enable); skipping");
        return { findings: [] };
      }
      throw err;
    }
    // Identify our own token once; it never changes id.
    let selfId = prev?.self;
    if (!selfId) selfId = await cf.get<{ id: string }>("/user/tokens/verify").then((r) => r.id).catch(() => undefined);
    const { findings, state } = diffTokens(prev, list, { now: now.getTime(), date: now.toISOString().slice(0, 10), selfId });
    // The hourly check reports only urgent changes; the rest wait for the digest.
    const out = ctx.schedule === "hourly" ? findings.filter((f) => f.severity === "urgent") : findings;
    // Hourly must not consume non-urgent changes: keep the old snapshot for
    // tokens whose non-urgent findings were held back.
    if (ctx.schedule === "hourly" && prev && out.length !== findings.length) return { findings: out, newState: prev };
    return { findings: out, stats: { account: { tokens: list.length } }, newState: state };
  },
};
