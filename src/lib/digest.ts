import { SEVERITY_ORDER, type Finding, type Severity } from "../types";
import type { Message } from "../notify/notifier";

export type ReportedFinding = Finding & {
  reason: "new" | "volume-jump" | "state-change";
  previousCount?: number;
};

const SEV_LABEL: Record<Severity, string> = {
  urgent: "🔴 URGENT",
  warning: "🟠 WARNING",
  info: "🔵 INFO",
};

const MAX_PER_ZONE = 15;

function annotate(f: ReportedFinding): string {
  if (f.reason === "volume-jump") return ` (↑ ${f.previousCount ?? "?"} → ${f.count ?? "?"})`;
  if (f.count && f.count > 1) return ` (×${f.count})`;
  return "";
}

/**
 * Render findings grouped by severity, then zone. Plain text, short lines,
 * readable on a phone. Account-level findings sort first within a severity.
 */
export function renderDigest(
  findings: ReportedFinding[],
  opts: { title: string; date: string; footer?: string[] },
): Message | null {
  if (findings.length === 0) return null;

  const counts = SEVERITY_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  const subject = `[alertflare] ${opts.title}: ${counts.join(", ")} (${opts.date})`;

  const lines: string[] = [];
  for (const sev of SEVERITY_ORDER) {
    const inSev = findings.filter((f) => f.severity === sev);
    if (!inSev.length) continue;
    lines.push(`${SEV_LABEL[sev]} (${inSev.length})`);
    const zones = [...new Set(inSev.map((f) => f.zone))].sort((a, b) =>
      a === "account" ? -1 : b === "account" ? 1 : a.localeCompare(b),
    );
    for (const zone of zones) {
      const inZone = inSev.filter((f) => f.zone === zone);
      lines.push(`  ▸ ${zone}`);
      for (const f of inZone.slice(0, MAX_PER_ZONE)) {
        lines.push(`    • ${f.summary}${annotate(f)}`);
        for (const d of f.details ?? []) lines.push(`      ${d}`);
        if (f.rayId) lines.push(`      Ray ${f.rayId}`);
        if (f.link) lines.push(`      ${f.link}`);
      }
      if (inZone.length > MAX_PER_ZONE) lines.push(`    … and ${inZone.length - MAX_PER_ZONE} more`);
    }
    lines.push("");
  }
  if (opts.footer?.length) lines.push("—", ...opts.footer);
  return { subject, text: lines.join("\n").trimEnd() + "\n" };
}

/** Weekly heartbeat: totals per collector and per zone. */
export function renderHeartbeat(
  totals: Record<string, Record<string, Record<string, number>>>,
  opts: { date: string; failures: string[]; lastRuns: Record<string, string | undefined> },
): Message {
  const lines: string[] = ["Weekly heartbeat: alertflare is running.", ""];
  for (const [sched, at] of Object.entries(opts.lastRuns)) {
    lines.push(`Last ${sched} run: ${at ?? "never"}`);
  }
  lines.push("");
  for (const collector of Object.keys(totals).sort()) {
    lines.push(`▸ ${collector}`);
    const byZone = totals[collector]!;
    for (const zone of Object.keys(byZone).sort()) {
      const metrics = Object.entries(byZone[zone]!)
        .map(([k, v]) => `${k}=${v}`)
        .join(", ");
      lines.push(`    ${zone}: ${metrics || "-"}`);
    }
  }
  if (opts.failures.length) {
    lines.push("", "Collector failures this week:", ...opts.failures.map((f) => `  • ${f}`));
  }
  return { subject: `[alertflare] Weekly heartbeat (${opts.date})`, text: lines.join("\n") + "\n" };
}
