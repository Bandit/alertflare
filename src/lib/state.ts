/**
 * "Already reported" state.
 *
 * Free-plan KV allows 1,000 writes/day, so state is stored as ONE JSON
 * document per collector (not one key per fingerprint) and only written when
 * it actually changed.
 *
 * Keys:
 *   reported:<collector>  -> ReportedState
 *   state:<collector>     -> collector-private state (snapshots etc.)
 *   failure:<collector>   -> ISO date of last reported failure (rate limit)
 *   stats:<yyyy-mm-dd>:<collector> -> daily stats for the weekly heartbeat
 *   heartbeat:last        -> ISO date of last heartbeat sent
 *   lastrun:<schedule>    -> ISO timestamp of last successful run
 */
import type { Finding } from "../types";

export interface ReportedEntry {
  /** count at last report (for volume-jump detection) */
  c: number;
  /** first reported (epoch ms) */
  f: number;
  /** last seen (epoch ms) */
  s: number;
  /** acknowledged: never re-report, even on volume jump */
  a?: 1;
}

export type ReportedState = Record<string, ReportedEntry>;

export interface DiffOptions {
  volumeJumpMultiplier: number;
  volumeJumpMinCount: number;
  forgetAfterDays: number;
  now: number;
}

export interface DiffResult {
  /** Findings to report now, with `reason` annotated. */
  toReport: (Finding & { reason: "new" | "volume-jump"; previousCount?: number })[];
  next: ReportedState;
  changed: boolean;
}

/**
 * Decide which findings are new or have jumped sharply in volume.
 * Pure function: callers persist `next` if `changed`.
 */
export function diffFindings(
  findings: Finding[],
  prev: ReportedState,
  opts: DiffOptions,
): DiffResult {
  const next: ReportedState = { ...prev };
  const toReport: DiffResult["toReport"] = [];
  let changed = false;
  const forgetMs = opts.forgetAfterDays * 86_400_000;

  // Merge duplicate fingerprints within one run.
  const merged = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.source}|${f.fingerprint}`;
    const existing = merged.get(key);
    if (existing) {
      existing.count = (existing.count ?? 0) + (f.count ?? 0);
    } else {
      merged.set(key, { ...f });
    }
  }

  for (const [key, f] of merged) {
    const old = next[key];
    const count = f.count ?? 1;
    if (!old) {
      toReport.push({ ...f, reason: "new" });
      next[key] = { c: count, f: opts.now, s: opts.now };
      changed = true;
      continue;
    }
    // Only bump "last seen" once a day to avoid needless KV writes.
    if (opts.now - old.s > 86_400_000 / 2) {
      next[key] = { ...old, s: opts.now };
      changed = true;
    }
    if (old.a || f.kind === "event") continue;
    if (
      count >= opts.volumeJumpMinCount &&
      count >= Math.max(1, old.c) * opts.volumeJumpMultiplier
    ) {
      toReport.push({ ...f, reason: "volume-jump", previousCount: old.c });
      next[key] = { ...next[key]!, c: count, s: opts.now };
      changed = true;
    }
  }

  // Forget entries unseen for a long time so a recurrence is reported again.
  for (const [key, e] of Object.entries(next)) {
    if (opts.now - e.s > forgetMs) {
      delete next[key];
      changed = true;
    }
  }

  return { toReport, next, changed };
}

export async function readJson<T>(kv: KVNamespace, key: string): Promise<T | undefined> {
  const v = await kv.get(key, "json");
  return (v ?? undefined) as T | undefined;
}

export async function writeJson(
  kv: KVNamespace,
  key: string,
  value: unknown,
  ttlSeconds?: number,
): Promise<void> {
  await kv.put(key, JSON.stringify(value), ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);
}
