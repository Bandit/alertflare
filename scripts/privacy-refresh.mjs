#!/usr/bin/env node
/**
 * Build .private-denylist.json: the real values that must never be committed
 * (zone names, hostnames, origin IPs, tunnel names/IDs, token names/IDs,
 * account ID, secrets from .dev.vars). Read-only API calls with the token in
 * .dev.vars. The file is gitignored and is as sensitive as .dev.vars.
 *
 * The "extra" list is yours to edit (words that would reveal your setup,
 * e.g. product names or rule names). It is kept across refreshes.
 *
 *   npm run privacy:refresh
 */
import fs from "node:fs";

const FILE = ".private-denylist.json";
// Cloudflare's built-in token template names: shared by everyone, not identifying.
const GENERIC_TOKEN_NAMES = new Set(["edit zone dns", "read all resources", "read billing info", "read analytics and logs"]);

function readDevVars() {
  if (!fs.existsSync(".dev.vars")) throw new Error(".dev.vars not found (needs CF_API_TOKEN and CF_ACCOUNT_ID)");
  return Object.fromEntries(
    fs.readFileSync(".dev.vars", "utf8").split("\n")
      .filter((l) => l.includes("=") && !l.trim().startsWith("#"))
      .map((l) => { const i = l.indexOf("="); return [l.slice(0, i).trim(), l.slice(i + 1).trim().replace(/^"|"$/g, "")]; }),
  );
}

const vars = readDevVars();
const headers = { Authorization: `Bearer ${vars.CF_API_TOKEN}` };
async function get(path) {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, { headers });
  const body = await res.json().catch(() => ({}));
  if (!body.success) { console.warn(`  skipped ${path.split("?")[0].replace(/[0-9a-f]{32}/g, "…")}: HTTP ${res.status}`); return []; }
  return body.result ?? [];
}

const values = new Map();
const add = (label, value) => {
  const v = String(value ?? "").trim();
  if (v.length >= 4 && !values.has(v.toLowerCase())) values.set(v.toLowerCase(), { label, value: v });
};

for (const k of ["CF_API_TOKEN", "CF_ACCOUNT_ID", "POSTMARK_SERVER_TOKEN"]) add(`secret ${k}`, vars[k]);
for (const e of `${vars.EMAIL_TO ?? ""},${vars.EMAIL_FROM ?? ""}`.split(",")) add("email address", e);

const zones = await get("/zones?per_page=50");
for (const z of zones) {
  add("zone ID", z.id);
  add("zone name", z.name);
  for (const r of await get(`/zones/${z.id}/dns_records?per_page=500`)) {
    if (r.name.toLowerCase() !== z.name.toLowerCase()) add("hostname", r.name);
    if (r.type === "A" || r.type === "AAAA") add("origin IP", r.content);
    if (r.type === "CNAME" && /cfargotunnel\.com\.?$/i.test(r.content)) add("tunnel ID", r.content.split(".")[0]);
  }
}
for (const t of await get(`/accounts/${vars.CF_ACCOUNT_ID}/cfd_tunnel?is_deleted=false&per_page=50`)) {
  add("tunnel ID", t.id);
  add("tunnel name", t.name);
  for (const c of t.connections ?? []) add("connector IP", c.origin_ip);
}
for (const t of await get("/user/tokens?per_page=50")) {
  add("API token ID", t.id);
  if (!GENERIC_TOKEN_NAMES.has(t.name.toLowerCase())) add("API token name", t.name);
}

const previous = fs.existsSync(FILE) ? JSON.parse(fs.readFileSync(FILE, "utf8")) : {};
const out = {
  _comment: "Gitignored. Real values that must never be committed. Regenerate with `npm run privacy:refresh`; edit `extra` by hand.",
  refreshedAt: new Date().toISOString(),
  extra: previous.extra ?? [],
  values: [...values.values()],
};
fs.writeFileSync(FILE, JSON.stringify(out, null, 2) + "\n", { mode: 0o600 });
const counts = {};
for (const v of out.values) counts[v.label] = (counts[v.label] ?? 0) + 1;
console.log(`Wrote ${FILE}: ${out.values.length} values (${Object.entries(counts).map(([k, n]) => `${n} ${k}`).join(", ")}), ${out.extra.length} extra terms.`);
