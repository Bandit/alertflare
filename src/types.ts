import type { Config } from "./config";
import type { CloudflareClient } from "./cf/client";

export type Severity = "urgent" | "warning" | "info";

export const SEVERITY_ORDER: Severity[] = ["urgent", "warning", "info"];

/** Normalised output of every collector. */
export interface Finding {
  /** Collector id, e.g. "security-events". */
  source: string;
  /**
   * Stable identity of the thing being reported. Two runs that see "the same
   * problem" must produce the same fingerprint. Never include timestamps.
   */
  fingerprint: string;
  severity: Severity;
  /** One line, phone-friendly. Must already be redacted. */
  summary: string;
  /** Optional extra lines (already redacted). */
  details?: string[];
  /** Zone name used for grouping; "account" for account-level findings. */
  zone: string;
  /** Volume metric used for the "jumped sharply" check (e.g. event count). */
  count?: number;
  link?: string;
  rayId?: string;
  /**
   * "event": report once, never again (audit log entry, state transition).
   * "recurring": re-report only when volume jumps by VOLUME_JUMP_MULTIPLIER.
   * Default "recurring".
   */
  kind?: "event" | "recurring";
}

export interface CollectorStats {
  /** Free-form totals for the weekly heartbeat, e.g. { events: 1234, noise: 1200 }. */
  [metric: string]: number;
}

export interface CollectorResult {
  findings: Finding[];
  /** Per-zone (or "account") totals for the weekly heartbeat. */
  stats?: Record<string, CollectorStats>;
  /** Collector-private state to persist (e.g. inventory snapshot, tunnel status). */
  newState?: unknown;
}

/** daily digest, hourly urgent check, frequent = every 5 minutes (tunnel health). */
export type Schedule = "daily" | "hourly" | "frequent";

export interface ZoneRef {
  id: string;
  name: string;
  plan?: string;
}

export interface CollectorContext {
  env: Env;
  config: Config;
  cf: CloudflareClient;
  /** Zones in the account, fetched once per run. */
  zones: () => Promise<ZoneRef[]>;
  /** Run start time. */
  now: Date;
  /** Collector-private state stored by the previous run (undefined on first run). */
  previousState: unknown;
  schedule: Schedule;
  log: (msg: string) => void;
}

export interface Collector {
  id: string;
  /** Human label for digests. */
  label: string;
  schedules: Schedule[];
  /** Return false to skip (e.g. disabled in config). */
  enabled?: (config: Config) => boolean;
  collect(ctx: CollectorContext): Promise<CollectorResult>;
}

export interface Env {
  ALERTFLARE_STATE: KVNamespace;
  EMAIL?: SendEmail;
  CF_API_TOKEN: string;
  CF_ACCOUNT_ID: string;
  [key: string]: unknown;
}
