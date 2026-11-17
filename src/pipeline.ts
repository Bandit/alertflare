import { loadConfig, type Config } from "./config";
import { BudgetExceededError, CloudflareApiError, CloudflareClient } from "./cf/client";
import { listZones, resolveAccountId } from "./cf/zones";
import { renderDigest, renderHeartbeat, type ReportedFinding } from "./lib/digest";
import { diffFindings, readJson, writeJson, type ReportedState } from "./lib/state";
import { redactText } from "./lib/normalise";
import { ConsoleNotifier, EmailNotifier, PostmarkNotifier, type Notifier } from "./notify/notifier";
import type { Collector, CollectorStats, Env, Finding, Schedule, ZoneRef } from "./types";

/**
 * Workers Free allows 50 external subrequests per invocation. Cloudflare API
 * calls get 47; the rest is kept for notifications (Postmark sends are
 * external fetches: digest + weekly heartbeat = 2).
 */
const SUBREQUEST_BUDGET = 47;
const DAY = 86_400;

export interface RunOptions {
  collectors: Collector[];
  /** Override the notifier (tests). */
  notifier?: Notifier;
  fetchImpl?: (input: string, init?: RequestInit) => Promise<Response>;
  /** Force the weekly heartbeat regardless of weekday. */
  forceHeartbeat?: boolean;
}

export interface RunReport {
  schedule: Schedule;
  reported: ReportedFinding[];
  failures: string[];
  subrequests: number;
  sent: string[];
}

export function makeNotifier(env: Env, config: Config): Notifier {
  if (config.dryRun) return new ConsoleNotifier();
  if (!config.emailFrom || config.emailTo.length === 0) {
    throw new Error("EMAIL_FROM and EMAIL_TO must be set (or set DRY_RUN=true)");
  }
  if (config.notifier === "postmark") {
    const token = env.POSTMARK_SERVER_TOKEN;
    if (typeof token !== "string" || !token) throw new Error("POSTMARK_SERVER_TOKEN secret missing");
    return new PostmarkNotifier(token, config.emailFrom, config.emailTo, config.postmarkStream);
  }
  if (!env.EMAIL) throw new Error("EMAIL send_email binding missing (or set DRY_RUN=true)");
  return new EmailNotifier(env.EMAIL, config.emailFrom, config.emailTo);
}

/** Local date parts in the configured timezone. */
export function localParts(now: Date, tz: string): { date: string; weekday: number } {
  const date = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" }).format(now);
  const wd = new Intl.DateTimeFormat("en-US", { timeZone: tz, weekday: "short" }).format(now);
  return { date, weekday: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"].indexOf(wd) };
}

function describeError(err: unknown): string {
  if (err instanceof BudgetExceededError) {
    return "ran out of subrequest budget (too many zones/pages for one invocation; see README 'Limits')";
  }
  if (err instanceof CloudflareApiError) {
    if (err.status === 401 || err.status === 403 || [9106, 9109, 10000, 10001].some((c) => err.codes.includes(c))) {
      return `permission denied: check the API token's permissions (${err.message})`;
    }
    if (/not authori[sz]ed/i.test(err.message)) {
      return `permission denied: the token needs Zone > Analytics > Read (${err.message})`;
    }
    return err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

export async function run(env: Env, schedule: Schedule, now: Date, opts: RunOptions): Promise<RunReport> {
  const config = loadConfig(env);
  const cf = new CloudflareClient(env.CF_API_TOKEN, SUBREQUEST_BUDGET, opts.fetchImpl);
  const kv = env.ALERTFLARE_STATE;
  const log = (m: string) => console.log(`[${schedule}] ${m}`);
  const local = localParts(now, config.timezone);

  let accountId: string | undefined;
  const account = async () => (accountId ??= await resolveAccountId(cf, env.CF_ACCOUNT_ID));
  let zonesPromise: Promise<ZoneRef[]> | undefined;
  const zones = () => (zonesPromise ??= account().then((a) => listZones(cf, a, config)));

  const report: RunReport = { schedule, reported: [], failures: [], subrequests: 0, sent: [] };
  const toSend: ReportedFinding[] = [];
  /**
   * State that depends on the notification going out ("reported" sets,
   * collector snapshots, failure rate-limit keys) is only persisted after a
   * successful send, so a failed send means "retry next run", not "lost".
   */
  const pending: { key: string; value: unknown; ttl?: number }[] = [];
  const dayStats: Record<string, Record<string, CollectorStats>> = {};

  const active = opts.collectors.filter(
    (c) =>
      c.schedules.includes(schedule) &&
      !config.disabledCollectors.includes(c.id) &&
      (c.enabled ? c.enabled(config) : true),
  );

  for (const collector of active) {
    try {
      // Make sure the account id is resolved before collectors use env.
      await account();
      const stateKey = `state:${collector.id}`;
      const previousState = await readJson<unknown>(kv, stateKey);
      const result = await collector.collect({
        env: { ...env, CF_ACCOUNT_ID: accountId! },
        config,
        cf,
        zones,
        now,
        previousState,
        schedule,
        log: (m) => log(`${collector.id}: ${m}`),
      });

      if (result.newState !== undefined && JSON.stringify(result.newState) !== JSON.stringify(previousState)) {
        pending.push({ key: stateKey, value: result.newState });
      }
      if (result.stats) dayStats[collector.id] = result.stats;

      const reportedKey = `reported:${collector.id}`;
      const prev = (await readJson<ReportedState>(kv, reportedKey)) ?? {};
      const diff = diffFindings(result.findings, prev, {
        volumeJumpMultiplier: config.volumeJumpMultiplier,
        volumeJumpMinCount: config.volumeJumpMinCount,
        forgetAfterDays: config.forgetAfterDays,
        now: now.getTime(),
      });
      if (diff.changed) pending.push({ key: reportedKey, value: diff.next });
      toSend.push(...diff.toReport);
      log(`${collector.id}: ${result.findings.length} findings, ${diff.toReport.length} to report`);
    } catch (err) {
      const msg = redactText(describeError(err));
      log(`${collector.id} FAILED: ${msg}`);
      report.failures.push(`${collector.id}: ${msg}`);
      // Rate-limit failure findings to once per day per collector.
      const failKey = `failure:${collector.id}`;
      if (!(await kv.get(failKey))) {
        pending.push({ key: failKey, value: now.toISOString(), ttl: DAY });
        toSend.push({
          source: "alertflare",
          fingerprint: `failure:${collector.id}`,
          severity: "warning",
          zone: "account",
          summary: `Collector "${collector.label}" failed: ${msg}`,
          reason: "new",
        });
      }
      await appendWeeklyFailure(kv, local.date, `${collector.id}: ${msg}`);
    }
  }

  const notifier = opts.notifier ?? makeNotifier(env, config);

  const footer = [`${config.dryRun ? "DRY RUN · " : ""}${schedule} run · ${cf.used} API calls`];
  const msg = renderDigest(toSend, {
    title: schedule === "hourly" ? "Urgent" : schedule === "frequent" ? "Tunnels" : "Daily digest",
    date: local.date,
    footer,
  });
  if (msg) {
    // If this throws, nothing below runs: findings stay "unreported" and are
    // retried next run instead of being silently lost.
    await notifier.send(msg);
    report.sent.push(msg.subject);
  } else {
    log("nothing new: not sending");
  }
  for (const p of pending) await writeJson(kv, p.key, p.value, p.ttl);

  // The 5-minute run would cost 288 KV writes a day for this alone.
  if (schedule !== "frequent") await kv.put(`lastrun:${schedule}`, now.toISOString());

  if (schedule === "daily") {
    if (Object.keys(dayStats).length) {
      await writeJson(kv, `stats:${local.date}`, dayStats, 9 * DAY);
    }
    if (opts.forceHeartbeat || local.weekday === config.heartbeatWeekday) {
      const hb = await buildHeartbeat(kv, now, config, local.date);
      await notifier.send(hb);
      report.sent.push(hb.subject);
    }
  }

  report.reported = toSend;
  report.subrequests = cf.used;
  return report;
}

async function appendWeeklyFailure(kv: KVNamespace, date: string, line: string): Promise<void> {
  const key = `failures:${date}`;
  const existing = (await readJson<string[]>(kv, key)) ?? [];
  if (existing.includes(line) || existing.length >= 20) return;
  existing.push(line);
  await writeJson(kv, key, existing, 9 * DAY);
}

async function buildHeartbeat(kv: KVNamespace, now: Date, config: Config, today: string) {
  const totals: Record<string, Record<string, Record<string, number>>> = {};
  const failures: string[] = [];
  for (let i = 0; i < 7; i++) {
    const d = localParts(new Date(now.getTime() - i * DAY * 1000), config.timezone).date;
    const stats = await readJson<Record<string, Record<string, CollectorStats>>>(kv, `stats:${d}`);
    for (const [collector, byZone] of Object.entries(stats ?? {})) {
      for (const [zone, metrics] of Object.entries(byZone)) {
        const t = (((totals[collector] ??= {})[zone] ??= {}));
        for (const [k, v] of Object.entries(metrics)) t[k] = (t[k] ?? 0) + v;
      }
    }
    for (const f of (await readJson<string[]>(kv, `failures:${d}`)) ?? []) failures.push(`${d} ${f}`);
  }
  const lastRuns = {
    daily: (await kv.get("lastrun:daily")) ?? undefined,
    hourly: (await kv.get("lastrun:hourly")) ?? undefined,
  };
  return renderHeartbeat(totals, { date: today, failures, lastRuns });
}

/** Exposed so ack tooling and tests can share the key format. */
export function reportedKey(f: Pick<Finding, "source" | "fingerprint">): string {
  return `${f.source}|${f.fingerprint}`;
}
