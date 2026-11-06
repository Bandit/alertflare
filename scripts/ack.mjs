#!/usr/bin/env node
/**
 * Acknowledge / list / reset "already reported" findings in KV.
 *
 *   npm run ack -- list   <collector>              # show fingerprints
 *   npm run ack -- ack    <collector> <substring>  # never re-report these (even on volume jump)
 *   npm run ack -- unack  <collector> <substring>
 *   npm run ack -- forget <collector> <substring>  # report again next run if still happening
 *
 * Add --local to operate on `wrangler dev` storage instead of production.
 * Collectors: security-events, audit-logs, access, inventory
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const where = args.includes("--local") ? "--local" : "--remote";
const [cmd, collector, match] = args.filter((a) => !a.startsWith("--"));
if (!cmd || !collector || (cmd !== "list" && !match)) {
  console.error("usage: npm run ack -- <list|ack|unack|forget> <collector> [substring] [--local]");
  process.exit(2);
}
const key = `reported:${collector}`;
const wrangler = (...a) => execFileSync("npx", ["wrangler", "kv", "key", ...a, "--binding", "ALERTFLARE_STATE", where], { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });

let state = {};
try {
  state = JSON.parse(wrangler("get", key, "--text") || "{}");
} catch {
  state = {};
}
const keys = Object.keys(state).filter((k) => !match || k.includes(match));

if (cmd === "list") {
  for (const k of keys) {
    const e = state[k];
    console.log(`${e.a ? "[ack] " : "      "}${k}  count=${e.c} first=${new Date(e.f).toISOString().slice(0, 10)} seen=${new Date(e.s).toISOString().slice(0, 10)}`);
  }
  process.exit(0);
}
if (keys.length === 0) {
  console.error(`no fingerprints in ${key} match "${match}"`);
  process.exit(1);
}
for (const k of keys) {
  if (cmd === "ack") state[k].a = 1;
  else if (cmd === "unack") delete state[k].a;
  else if (cmd === "forget") delete state[k];
  else {
    console.error(`unknown command ${cmd}`);
    process.exit(2);
  }
  console.log(`${cmd}: ${k}`);
}
const dir = mkdtempSync(join(tmpdir(), "alertflare-"));
const file = join(dir, "state.json");
writeFileSync(file, JSON.stringify(state));
try {
  wrangler("put", key, "--path", file);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
