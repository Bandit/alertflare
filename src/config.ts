import type { Env } from "./types";

/**
 * Generic scanner paths. Matches here are counted (for the weekly heartbeat)
 * but never alerted on, regardless of method or volume.
 *
 * Glob syntax: `*` matches any run of characters (including `/`), `?` one
 * character. Matching is case-insensitive and against the *raw* path
 * (no query string).
 */
export const DEFAULT_IGNORE_PATHS = [
  "/wp-*",
  "*/wp-admin*",
  "*/wp-includes*",
  "*/wp-content*",
  "*/wp-login*",
  "*/xmlrpc.php*",
  "*.php",
  "*.php7",
  "*.asp",
  "*.aspx",
  "*.jsp",
  "*.cgi",
  "/cgi-bin/*",
  "*/.env*",
  "*/.git/*",
  "*/.git",
  "*/.svn/*",
  "*/.hg/*",
  "*/.ds_store",
  "*/.aws/*",
  "*/.ssh/*",
  "*/.vscode/*",
  "*/.idea/*",
  "/phpmyadmin*",
  "/pma*",
  "/myadmin*",
  "/admin.php*",
  "/boaform/*",
  "/actuator*",
  "/vendor/phpunit*",
  "/owa/*",
  "/ecp/*",
  "/autodiscover*",
  "/remote/login*",
  "/geoserver*",
  "/solr/*",
  "/hnap1*",
  "/sdk",
  "/shell*",
  "/console*",
  "/server-status*",
  "/config.json",
  "/config.js",
  "/backup*",
  "*.sql",
  "*.bak",
  "*.zip",
  "*.tar.gz",
  "/robots.txt",
  "/sitemap.xml",
  "/favicon.ico",
  "/ads.txt",
  "/security.txt",
  "/.well-known/security.txt",
];

/** Paths that make an otherwise-ordinary blocked request "interesting". */
export const DEFAULT_INTERESTING_PATHS = ["/api/*"];

export interface Config {
  dryRun: boolean;
  /** "postmark" or "cloudflare" (send_email binding). */
  notifier: "postmark" | "cloudflare";
  postmarkStream: string;
  emailFrom: string;
  emailTo: string[];
  ignorePaths: string[];
  interestingPaths: string[];
  interestingMethods: string[];
  /** Hits from a single ASN on one fingerprint before it is interesting. */
  asnRepeatThreshold: number;
  /** Re-report a recurring finding when count >= previous * multiplier. */
  volumeJumpMultiplier: number;
  /** Ignore volume jumps where the new count is below this. */
  volumeJumpMinCount: number;
  /** Forget a reported fingerprint after this many days unseen. */
  forgetAfterDays: number;
  /** Local day (in `timezone`) for the weekly heartbeat. 0=Sun..6=Sat. */
  heartbeatWeekday: number;
  timezone: string;
  /** Only these zones (names), empty = all. */
  zoneInclude: string[];
  zoneExclude: string[];
  disabledCollectors: string[];
  /** Max zones processed per invocation (subrequest budget). */
  maxZonesPerRun: number;
  /** Countries considered "normal" for logins; empty = learn from history only. */
  loginHomeCountries: string[];
}

function list(v: unknown): string[] {
  if (typeof v !== "string") return [];
  return v
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function num(v: unknown, fallback: number): number {
  if (typeof v !== "string" || v.trim() === "") return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function bool(v: unknown): boolean {
  return typeof v === "string" && ["1", "true", "yes", "on"].includes(v.trim().toLowerCase());
}

const WEEKDAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

function weekday(v: unknown, fallback: number): number {
  if (typeof v !== "string") return fallback;
  const i = WEEKDAYS.indexOf(v.trim().slice(0, 3).toLowerCase());
  return i >= 0 ? i : fallback;
}

export function loadConfig(env: Env): Config {
  const replaceIgnore = list(env.IGNORE_PATHS);
  return {
    dryRun: bool(env.DRY_RUN),
    notifier:
      env.NOTIFIER === "cloudflare" || env.NOTIFIER === "postmark"
        ? env.NOTIFIER
        : typeof env.POSTMARK_SERVER_TOKEN === "string" && env.POSTMARK_SERVER_TOKEN
          ? "postmark"
          : "cloudflare",
    postmarkStream: typeof env.POSTMARK_MESSAGE_STREAM === "string" && env.POSTMARK_MESSAGE_STREAM ? env.POSTMARK_MESSAGE_STREAM : "outbound",
    emailFrom: typeof env.EMAIL_FROM === "string" ? env.EMAIL_FROM : "",
    emailTo: list(env.EMAIL_TO),
    ignorePaths: [
      ...(replaceIgnore.length ? replaceIgnore : DEFAULT_IGNORE_PATHS),
      ...list(env.EXTRA_IGNORE_PATHS),
    ],
    interestingPaths: list(env.INTERESTING_PATHS).length
      ? list(env.INTERESTING_PATHS)
      : DEFAULT_INTERESTING_PATHS,
    interestingMethods: (list(env.INTERESTING_METHODS).length
      ? list(env.INTERESTING_METHODS)
      : ["POST", "PUT", "PATCH", "DELETE"]
    ).map((m) => m.toUpperCase()),
    asnRepeatThreshold: num(env.ASN_REPEAT_THRESHOLD, 50),
    volumeJumpMultiplier: num(env.VOLUME_JUMP_MULTIPLIER, 3),
    volumeJumpMinCount: num(env.VOLUME_JUMP_MIN_COUNT, 20),
    forgetAfterDays: num(env.FORGET_AFTER_DAYS, 30),
    heartbeatWeekday: weekday(env.HEARTBEAT_DAY, 1),
    timezone: typeof env.TIMEZONE === "string" && env.TIMEZONE ? env.TIMEZONE : "UTC",
    zoneInclude: list(env.ZONES_INCLUDE).map((z) => z.toLowerCase()),
    zoneExclude: list(env.ZONES_EXCLUDE).map((z) => z.toLowerCase()),
    disabledCollectors: list(env.DISABLED_COLLECTORS),
    maxZonesPerRun: num(env.MAX_ZONES_PER_RUN, 10),
    loginHomeCountries: list(env.LOGIN_HOME_COUNTRIES).map((c) => c.toUpperCase()),
  };
}
