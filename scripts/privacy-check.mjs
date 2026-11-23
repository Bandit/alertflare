#!/usr/bin/env node
/**
 * Block commits that contain real infrastructure values or setup hints.
 * Compares text against .private-denylist.json (gitignored; build it with
 * `npm run privacy:refresh`). Never prints the matched value itself.
 *
 *   node scripts/privacy-check.mjs --staged          added lines in the staged diff (pre-commit hook)
 *   node scripts/privacy-check.mjs --message FILE    a commit message (commit-msg hook)
 *   node scripts/privacy-check.mjs --all             every tracked file at HEAD + working tree
 *
 * Without the denylist it warns and allows the commit, so contributors
 * without one aren't blocked.
 */
import fs from "node:fs";
import { execFileSync } from "node:child_process";

const FILE = ".private-denylist.json";
const MAX_AGE_DAYS = 30;

if (!fs.existsSync(FILE)) {
  console.warn(`privacy-check: ${FILE} not found; skipping. Run \`npm run privacy:refresh\` to enable.`);
  process.exit(0);
}
const list = JSON.parse(fs.readFileSync(FILE, "utf8"));
const ageDays = (Date.now() - Date.parse(list.refreshedAt ?? 0)) / 86_400_000;
if (!(ageDays < MAX_AGE_DAYS)) console.warn(`privacy-check: ${FILE} is ${Math.floor(ageDays)} days old; run \`npm run privacy:refresh\`.`);

const entries = [
  ...(list.values ?? []),
  ...(list.extra ?? []).map((v) => (typeof v === "string" ? { label: "setup term", value: v } : v)),
].filter((e) => e.value && String(e.value).length >= 3);

const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// Whole-word match ("acme" matches "tunnel-acme" but not "acmeville").
const matchers = entries.map((e) => ({
  label: e.label,
  hint: String(e.value).length > 8 ? `${String(e.value).slice(0, 2)}…` : `${String(e.value)[0]}…`,
  re: new RegExp(`(^|[^A-Za-z0-9_])${escape(String(e.value))}(?=$|[^A-Za-z0-9_])`, "i"),
}));

function scan(source, lineNo, text, hits) {
  for (const m of matchers) if (m.re.test(text)) hits.push(`${source}${lineNo ? `:${lineNo}` : ""}  ${m.label} (${m.hint})`);
}

const args = process.argv.slice(2);
const hits = [];
const git = (...a) => execFileSync("git", a, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });

if (args[0] === "--staged") {
  let file = "";
  let line = 0;
  for (const l of git("diff", "--cached", "--unified=0", "--no-color", "--", ".", `:!${FILE}`).split("\n")) {
    if (l.startsWith("+++ ")) { file = l.slice(6); continue; }
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)/.exec(l);
    if (h) { line = Number(h[1]); continue; }
    if (l.startsWith("+")) { scan(file, line, l.slice(1), hits); line++; }
  }
} else if (args[0] === "--message") {
  const text = fs.readFileSync(args[1], "utf8").split("\n").filter((l) => !l.startsWith("#"));
  text.forEach((l, i) => scan("commit message", i + 1, l, hits));
} else if (args[0] === "--all") {
  for (const f of git("ls-files").split("\n").filter(Boolean)) {
    if (f === "package-lock.json" || !fs.existsSync(f)) continue;
    fs.readFileSync(f, "utf8").split("\n").forEach((l, i) => scan(f, i + 1, l, hits));
  }
} else {
  console.error("usage: privacy-check.mjs --staged | --message FILE | --all");
  process.exit(2);
}

if (hits.length) {
  console.error("privacy-check: real infrastructure values or setup terms found. Use placeholders (example.test, tunnel-a, …):");
  for (const h of hits) console.error(`  ${h}`);
  console.error("Fix them, or if this is a false positive, adjust .private-denylist.json.");
  process.exit(1);
}
