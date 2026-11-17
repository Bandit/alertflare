/**
 * Tunnel health, debounced. A replacement for Cloudflare's native "Tunnel
 * Health Alert", which emails on every state flip (one flapping connection
 * can send a dozen emails in ten minutes).
 *
 *   GET /accounts/{id}/cfd_tunnel?is_deleted=false   Permission: Cloudflare Tunnel Read
 *
 * Status values (API docs): healthy, degraded (serving traffic but some
 * connections lost), down (no connections, can't serve traffic), inactive
 * (never run). Seen on a live account (Nov 2026): `conns_inactive_at` is set
 * while a tunnel has no connections and is null again once it reconnects,
 * and `conns_active_at` moves to the reconnect time. So an ongoing outage is
 * timed from `conns_inactive_at`, and a *new* `conns_active_at` means the
 * tunnel dropped and came back, even if that happened between two polls.
 *
 * Two collectors share this file:
 *  - `tunnels` (every 5 minutes, "frequent"): urgent alert once a tunnel has
 *    been down for TUNNEL_DOWN_GRACE_MINUTES; one recovery message after an
 *    alert. Blips shorter than the grace period never alert. It is the only
 *    writer of `state:tunnels` and writes only when something changes (KV
 *    write limits: 288 runs a day).
 *  - `tunnel-summary` (daily): one digest line per tunnel that dropped or
 *    degraded since the last summary. Reads `state:tunnels`, never writes it,
 *    so it can't race the 5-minute run that fires at the same minute.
 *
 * Without the permission the API returns 200 with an empty list, not an
 * error, so "all tunnels vanished" is reported as a failure, not as calm.
 */
import { readJson } from "../lib/state";
import type { Collector, Finding } from "../types";

const LINK = "https://one.dash.cloudflare.com/";
const EVENT_RETENTION_MS = 3 * 86_400_000;
const MAX_EVENTS = 200;

export interface ApiTunnel {
  id: string;
  name: string;
  status: string;
  conns_active_at?: string | null;
  conns_inactive_at?: string | null;
}

interface TunnelRec {
  name: string;
  status: string;
  /** conns_active_at last seen; a new value = it dropped and reconnected. */
  activeAt?: string;
  /** conns_inactive_at last seen (set only while it has no connections). */
  inactiveAt?: string;
  /** When we first saw it down, if the API gave no conns_inactive_at. */
  downSeenAt?: string;
  /** Outage (inactiveAt/downSeenAt) we already sent an urgent alert for. */
  alertedFor?: string;
}

export interface TunnelEvent {
  id: string;
  name: string;
  kind: "drop" | "degraded";
  at: string;
  /** Set when a drop is followed by recovery. */
  upAt?: string;
  alerted?: boolean;
}

export interface TunnelsState {
  tunnels: Record<string, TunnelRec>;
  events: TunnelEvent[];
}

const minutes = (ms: number) => Math.max(1, Math.round(ms / 60_000));

export function pollTunnels(
  prev: TunnelsState | undefined,
  list: ApiTunnel[],
  opts: { now: number; graceMinutes: number },
): { findings: Finding[]; state: TunnelsState } {
  const nowIso = new Date(opts.now).toISOString();
  const state: TunnelsState = {
    tunnels: {},
    events: (prev?.events ?? []).filter((e) => opts.now - Date.parse(e.at) < EVENT_RETENTION_MS).map((e) => ({ ...e })),
  };
  const findings: Finding[] = [];
  const add = (fingerprint: string, severity: Finding["severity"], summary: string, details?: string[]) =>
    findings.push({ source: "tunnels", fingerprint, severity, summary, details, zone: "account", link: LINK, kind: "event" });

  for (const t of list) {
    if (t.status === "inactive") continue; // never run: nothing to watch
    const old = prev?.tunnels[t.id];
    const rec: TunnelRec = {
      name: t.name,
      status: t.status,
      activeAt: t.conns_active_at ?? old?.activeAt,
      inactiveAt: t.conns_inactive_at ?? old?.inactiveAt,
      downSeenAt: old?.downSeenAt,
      alertedFor: old?.alertedFor,
    };
    const inactiveAt = t.conns_inactive_at ?? undefined;
    const activeAt = t.conns_active_at ?? undefined;
    const openDrop = () => [...state.events].reverse().find((e) => e.id === t.id && e.kind === "drop" && !e.upAt);

    if (t.status === "down" && !inactiveAt && !rec.downSeenAt) rec.downSeenAt = nowIso;
    const downSince = t.status === "down" ? (inactiveAt ?? rec.downSeenAt!) : undefined;

    if (old) {
      // Seen down (or a new "lost all connections" time): open a drop event.
      const newInactive = inactiveAt && inactiveAt !== old.inactiveAt;
      if ((downSince || newInactive) && !openDrop()) {
        state.events.push({ id: t.id, name: t.name, kind: "drop", at: downSince ?? inactiveAt! });
      }
      // Reconnected: close the open drop, or record a blip we never saw.
      if (activeAt && old.activeAt && activeAt !== old.activeAt && t.status !== "down") {
        const ev = openDrop();
        if (ev) ev.upAt = activeAt;
        else state.events.push({ id: t.id, name: t.name, kind: "drop", at: inactiveAt ?? activeAt, upAt: activeAt });
      }
      if (t.status === "degraded" && old.status !== "degraded") {
        state.events.push({ id: t.id, name: t.name, kind: "degraded", at: nowIso });
      }
    }

    if (downSince) {
      const downMs = opts.now - Date.parse(downSince);
      if (downMs >= opts.graceMinutes * 60_000 && rec.alertedFor !== downSince) {
        rec.alertedFor = downSince;
        add(`down|${t.id}|${downSince}`, "urgent", `Tunnel ${t.name} is down (for ${minutes(downMs)} min)`, [
          "No connections to Cloudflare: hostnames on this tunnel are unreachable",
          "Check the cloudflared host and its internet connection",
        ]);
        const ev = openDrop();
        if (ev) ev.alerted = true;
      }
    } else {
      rec.downSeenAt = undefined;
      const ev = openDrop();
      if (ev && old?.status === "down") ev.upAt = activeAt && activeAt !== old.activeAt ? activeAt : nowIso;
      if (rec.alertedFor) {
        const downMs = opts.now - Date.parse(rec.alertedFor);
        add(`up|${t.id}|${rec.alertedFor}`, "info", `Tunnel ${t.name} recovered (${t.status}) after about ${minutes(downMs)} min`);
        rec.alertedFor = undefined;
      }
    }
    state.tunnels[t.id] = rec;
  }
  if (state.events.length > MAX_EVENTS) state.events = state.events.slice(-MAX_EVENTS);
  return { findings, state };
}

export function summariseEvents(events: TunnelEvent[], sinceMs: number, untilMs: number, date: string): Finding[] {
  const byTunnel = new Map<string, { name: string; drops: number; degraded: number; alerted: number; longestMs: number }>();
  for (const e of events) {
    const at = Date.parse(e.at);
    if (at <= sinceMs || at > untilMs) continue;
    const s = byTunnel.get(e.id) ?? { name: e.name, drops: 0, degraded: 0, alerted: 0, longestMs: 0 };
    s.name = e.name;
    if (e.kind === "drop") {
      s.drops++;
      if (e.alerted) s.alerted++;
      if (e.upAt) s.longestMs = Math.max(s.longestMs, Date.parse(e.upAt) - at);
    } else s.degraded++;
    byTunnel.set(e.id, s);
  }
  const findings: Finding[] = [];
  for (const [id, s] of byTunnel) {
    const parts = [];
    if (s.drops) parts.push(`went down ${s.drops}×`);
    if (s.degraded) parts.push(`degraded ${s.degraded}×`);
    const details = [];
    if (s.longestMs) details.push(`longest outage about ${minutes(s.longestMs)} min`);
    if (s.alerted) details.push(`${s.alerted} outage${s.alerted === 1 ? "" : "s"} long enough to alert`);
    else if (s.drops) details.push("each recovered before the alert grace period");
    findings.push({
      source: "tunnel-summary",
      fingerprint: `${id}|${date}`,
      severity: s.drops >= 3 || s.alerted ? "warning" : "info",
      summary: `Tunnel ${s.name} ${parts.join(", ")} since the last digest`,
      details,
      zone: "account",
      link: LINK,
      kind: "event",
    });
  }
  return findings;
}

export const tunnels: Collector = {
  id: "tunnels",
  label: "Tunnel health",
  schedules: ["frequent"],

  async collect(ctx) {
    const prev = ctx.previousState as TunnelsState | undefined;
    const list = await ctx.cf.getAllPages<ApiTunnel>(`/accounts/${ctx.env.CF_ACCOUNT_ID}/cfd_tunnel?is_deleted=false`, 50, 2);
    const known = Object.keys(prev?.tunnels ?? {}).length;
    if (list.length === 0 && known > 0) {
      throw new Error(`tunnel list came back empty (was ${known}): the token may have lost Cloudflare Tunnel Read`);
    }
    const { findings, state } = pollTunnels(prev, list, { now: ctx.now.getTime(), graceMinutes: ctx.config.tunnelDownGraceMinutes });
    return { findings, newState: state };
  },
};

interface SummaryState {
  summarisedUntil: string;
}

export const tunnelSummary: Collector = {
  id: "tunnel-summary",
  label: "Tunnel summary",
  schedules: ["daily"],

  async collect(ctx) {
    const prev = ctx.previousState as SummaryState | undefined;
    const now = ctx.now.getTime();
    const since = prev ? Date.parse(prev.summarisedUntil) : now - 86_400_000;
    const tunnelState = await readJson<TunnelsState>(ctx.env.ALERTFLARE_STATE, "state:tunnels");
    const findings = summariseEvents(tunnelState?.events ?? [], since, now, ctx.now.toISOString().slice(0, 10));
    return { findings, newState: { summarisedUntil: ctx.now.toISOString() } };
  },
};
