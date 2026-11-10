/**
 * Domain health: things that can take a whole domain offline or hand it to
 * someone else, as opposed to changes *inside* a zone (see inventory).
 *
 *   GET /zones?account.id=…                         Zone Read     status, assigned nameservers
 *   GET /zones/{id}/dnssec                          Zone Read     DNSSEC status
 *   GET /accounts/{id}/registrar/registrations      Registrar: Domains Read (optional)
 *   Registry lookup per zone apex                   public, no auth:
 *     RDAP (IANA bootstrap, e.g. Verisign for .com/.net), or
 *     WHOIS on TCP 43 for TLDs without RDAP (.nz: whois.irs.net.nz)
 *
 * The registry lookup is the independent check: it shows which nameservers
 * the *registry* delegates the domain to. If that stops matching the
 * nameservers Cloudflare assigned, someone changed the domain at the
 * registrar (the classic hijack), even though nothing changed in Cloudflare.
 *
 * The registrations API replaced GET …/registrar/domains (end of life
 * 2026-09-27). Without the Registrar permission (403) that part is skipped
 * quietly. .nz WHOIS has no expiry date; expiry for .nz comes only from
 * the registrar API, i.e. for domains registered at Cloudflare.
 */
import { CloudflareApiError } from "../cf/client";
import { dashLink, filterZones } from "../cf/zones";
import type { Collector, CollectorStats, Finding } from "../types";

const DAY = 86_400_000;
const BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_TTL_MS = 30 * DAY;
const LOOKUP_TIMEOUT_MS = 8000;
/** TLDs without an RDAP service in the IANA bootstrap (checked Nov 2026). */
export const WHOIS_SERVERS: Record<string, string> = { nz: "whois.irs.net.nz" };

// ---------- types ----------

export interface ApiZone {
  id: string;
  name: string;
  status: string;
  name_servers?: string[];
}

export interface Registration {
  domain_name: string;
  status: string;
  expires_at: string | null;
  auto_renew: boolean;
  locked: boolean;
}

/** What the registry says, from RDAP or WHOIS. */
export interface RegistryInfo {
  nameservers: string[];
  registrar?: string;
  statuses: string[];
  signed?: boolean;
  expiresAt?: string;
  source: "rdap" | "whois";
}

export interface DomainSnapshot {
  zoneStatus?: string;
  dnssec?: string;
  registrar?: string;
  autoRenew?: boolean;
  locked?: boolean;
}

export interface DomainsState {
  domains: Record<string, DomainSnapshot>;
  rdap?: { fetchedAt: number; services: [string[], string[]][] };
}

export type Lookup = (domain: string) => Promise<RegistryInfo | undefined>;

// ---------- parsing ----------

const lower = (s: string) => s.toLowerCase().replace(/\.$/, "");

export function parseWhois(text: string): RegistryInfo {
  const info: RegistryInfo = { nameservers: [], statuses: [], source: "whois" };
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([^:%>#]+?):\s*(.*?)\s*$/.exec(line);
    if (!m || !m[2]) continue;
    const key = m[1]!.toLowerCase();
    const value = m[2];
    if (key === "name server" || key === "nserver") info.nameservers.push(lower(value.split(/\s+/)[0]!));
    else if (key === "registrar") info.registrar = value;
    else if (key === "domain status") info.statuses.push(value.split(/\s+/)[0]!);
    else if (key === "dnssec") info.signed = /^signed|^yes/i.test(value) && !/unsigned/i.test(value);
    else if (key === "registry expiry date" || key === "registrar registration expiration date") info.expiresAt = value;
  }
  info.nameservers = [...new Set(info.nameservers)].sort();
  return info;
}

interface RdapDomain {
  status?: string[];
  events?: { eventAction: string; eventDate: string }[];
  nameservers?: { ldhName?: string }[];
  secureDNS?: { delegationSigned?: boolean };
  entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, string, unknown][]] }[];
}

export function parseRdap(d: RdapDomain): RegistryInfo {
  const registrar = d.entities
    ?.find((e) => e.roles?.includes("registrar"))
    ?.vcardArray?.[1]?.find((p) => p[0] === "fn")?.[3];
  return {
    nameservers: [...new Set((d.nameservers ?? []).map((n) => lower(n.ldhName ?? "")).filter(Boolean))].sort(),
    registrar: typeof registrar === "string" ? registrar : undefined,
    statuses: d.status ?? [],
    signed: d.secureDNS?.delegationSigned,
    expiresAt: d.events?.find((e) => e.eventAction === "expiration")?.eventDate,
    source: "rdap",
  };
}

export function rdapBase(services: [string[], string[]][], domain: string): string | undefined {
  const tld = domain.split(".").pop()!.toLowerCase();
  const urls = services.find(([tlds]) => tlds.includes(tld))?.[1];
  const url = urls?.find((u) => u.startsWith("https://")) ?? urls?.[0];
  return url && (url.endsWith("/") ? url : url + "/");
}

// ---------- network lookups (not Cloudflare API calls) ----------

async function whoisQuery(server: string, domain: string): Promise<string> {
  // Dynamic import: only resolvable inside workerd, so tests never load it.
  const { connect } = await import("cloudflare:sockets");
  const socket = connect({ hostname: server, port: 43 });
  const timer = setTimeout(() => socket.close().catch(() => {}), LOOKUP_TIMEOUT_MS);
  try {
    const writer = socket.writable.getWriter();
    await writer.write(new TextEncoder().encode(`${domain}\r\n`));
    writer.releaseLock();
    const reader = socket.readable.getReader();
    const decoder = new TextDecoder();
    let text = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
      if (text.length > 64_000) break;
    }
    return text;
  } finally {
    clearTimeout(timer);
    await socket.close().catch(() => {});
  }
}

export function makeLookup(services: [string[], string[]][], fetchImpl: typeof fetch = fetch): Lookup {
  return async (domain) => {
    const tld = domain.split(".").pop()!.toLowerCase();
    const base = rdapBase(services, domain);
    if (base) {
      const res = await fetchImpl(`${base}domain/${domain}`, {
        headers: { accept: "application/rdap+json" },
        signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`RDAP ${res.status}`);
      return parseRdap((await res.json()) as RdapDomain);
    }
    const server = WHOIS_SERVERS[tld];
    if (server) return parseWhois(await whoisQuery(server, domain));
    return undefined;
  };
}

// ---------- analysis ----------

export interface DomainInput {
  zone: ApiZone;
  dnssec?: string;
  registration?: Registration;
  registry?: RegistryInfo;
}

const URGENT_REGISTRY_STATUS = /hold|redemption|pending ?delete|pendingdelete|inactive/i;
const LOCK_STATUS = /transfer ?prohibited/i;

export function analyseDomain(
  input: DomainInput,
  prev: DomainSnapshot | undefined,
  opts: { now: number; expiryWarnDays: number; date: string },
): { findings: Finding[]; snapshot: DomainSnapshot } {
  const { zone, dnssec, registration: reg, registry } = input;
  const name = zone.name;
  const findings: Finding[] = [];
  const add = (fingerprint: string, severity: Finding["severity"], summary: string, details?: string[], link?: string, kind: Finding["kind"] = "recurring") =>
    findings.push({ source: "domains", fingerprint: `${name}|${fingerprint}`, severity, summary, details, zone: name, link: link ?? dashLink(name, ""), kind });
  const event = (fp: string, severity: Finding["severity"], summary: string, details?: string[], link?: string) =>
    add(`${fp}|${opts.date}`, severity, summary, details, link, "event");
  const registrarLink = dashLink(undefined, "domains");
  const dnsLink = dashLink(name, "dns/settings");

  // Zone status (reported once while it persists).
  if (zone.status !== "active") {
    if (zone.status === "moved") {
      add(`zone-status|moved`, "urgent", `${name} is "moved": its nameservers no longer point at Cloudflare`, ["The domain is not being served by Cloudflare; check the registrar"]);
    } else {
      add(`zone-status|${zone.status}`, "warning", `${name} zone status is "${zone.status}"`);
    }
  } else if (prev?.zoneStatus && prev.zoneStatus !== "active") {
    event(`zone-active`, "info", `${name} is active on Cloudflare again (was "${prev.zoneStatus}")`);
  }

  // Registry delegation: the hijack check.
  const assigned = (zone.name_servers ?? []).map(lower).sort();
  if (registry && registry.nameservers.length && assigned.length && zone.status === "active") {
    const same = registry.nameservers.length === assigned.length && registry.nameservers.every((n, i) => n === assigned[i]);
    if (!same) {
      add(`registry-ns|${registry.nameservers.join(",")}`, "urgent", `${name}: the registry delegates to different nameservers than Cloudflare assigned`, [
        `registry: ${registry.nameservers.join(", ")}`,
        `Cloudflare: ${assigned.join(", ")}`,
        "If you didn't change this at your registrar, treat it as a possible domain hijack",
      ], registrarLink);
    }
  }
  if (registry) {
    for (const s of registry.statuses.filter((s) => URGENT_REGISTRY_STATUS.test(s))) {
      add(`registry-status|${s}`, "urgent", `${name} has registry status "${s}"`, ["The domain may stop resolving or be released"], registrarLink);
    }
  }

  // DNSSEC.
  if (dnssec === "error") add(`dnssec|error`, "warning", `${name}: DNSSEC is in an error state`, undefined, dnsLink);
  if (registry?.signed === true && dnssec && dnssec !== "active" && dnssec !== "pending-disabled") {
    add(`dnssec-mismatch|${dnssec}`, "urgent", `${name}: the registry has a DS record but Cloudflare DNSSEC is "${dnssec}"`, ["Validating resolvers will fail to resolve the domain"], dnsLink);
  }
  if (prev?.dnssec && dnssec && prev.dnssec !== dnssec) {
    const off = prev.dnssec === "active" && dnssec !== "active";
    event(`dnssec-change|${prev.dnssec}->${dnssec}`, off ? "warning" : "info", `${name}: DNSSEC ${prev.dnssec} → ${dnssec}`, undefined, dnsLink);
  }

  // Registrar change (from the registry's point of view).
  if (registry?.registrar && prev?.registrar && registry.registrar !== prev.registrar) {
    event(`registrar|${registry.registrar}`, "warning", `${name}: registrar changed from ${prev.registrar} to ${registry.registrar}`, ["Expected if you just transferred it; otherwise investigate"], registrarLink);
  }
  const registryLocked = registry ? registry.statuses.some((s) => LOCK_STATUS.test(s)) : undefined;
  if (!reg && registry?.source === "rdap" && prev?.locked === true && registryLocked === false) {
    event("unlocked", "warning", `${name}: transfer lock was removed at the registry`, ["Only expected right before transferring the domain away"], registrarLink);
  }

  // Registrar API (Cloudflare Registrar domains only).
  if (reg) {
    if (reg.status !== "active") {
      add(`registration|${reg.status}`, reg.status === "transfer_pending" || reg.status === "registration_pending" ? "info" : "urgent",
        `${name} registration status is "${reg.status}"`, undefined, registrarLink);
    }
    if (prev?.autoRenew === true && !reg.auto_renew) event("auto-renew-off", "warning", `${name}: auto-renew was turned off`, undefined, registrarLink);
    if (prev?.autoRenew === false && reg.auto_renew) event("auto-renew-on", "info", `${name}: auto-renew was turned on`, undefined, registrarLink);
    if (prev?.locked === true && !reg.locked) event("unlocked", "warning", `${name}: transfer lock was removed`, ["Only expected right before transferring the domain away"], registrarLink);
  }

  // Expiry: registrar API first (knows auto-renew), then registry.
  const expiresAt = reg?.expires_at ?? registry?.expiresAt;
  if (expiresAt) {
    const days = Math.floor((Date.parse(expiresAt) - opts.now) / DAY);
    const autoRenew = reg ? reg.auto_renew : undefined;
    let severity: Finding["severity"] | undefined;
    if (days <= 7) severity = "urgent";
    else if (days <= opts.expiryWarnDays && autoRenew !== true) severity = "warning";
    if (severity) {
      const renew = autoRenew === undefined ? "auto-renew unknown" : autoRenew ? "auto-renew on" : "auto-renew OFF";
      add(`expiry|${expiresAt.slice(0, 10)}|${severity}`, severity,
        days < 0 ? `${name} expired on ${expiresAt.slice(0, 10)}` : `${name} expires in ${days} day${days === 1 ? "" : "s"} (${expiresAt.slice(0, 10)}, ${renew})`,
        undefined, registrarLink);
    }
  }

  return {
    findings,
    snapshot: {
      zoneStatus: zone.status,
      dnssec: dnssec ?? prev?.dnssec,
      registrar: registry?.registrar ?? prev?.registrar,
      autoRenew: reg ? reg.auto_renew : prev?.autoRenew,
      // .nz WHOIS has no lock concept, so only RDAP statuses count.
      locked: reg ? reg.locked : registry?.source === "rdap" ? registryLocked : prev?.locked,
    },
  };
}

// ---------- collector ----------

async function listRegistrations(ctx: Parameters<Collector["collect"]>[0]): Promise<Map<string, Registration> | undefined> {
  const out = new Map<string, Registration>();
  let cursor = "";
  for (let page = 0; page < 5; page++) {
    let env;
    try {
      env = await ctx.cf.getEnvelope<Registration[]>(
        `/accounts/${ctx.env.CF_ACCOUNT_ID}/registrar/registrations?per_page=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
      );
    } catch (err) {
      if (err instanceof CloudflareApiError && [401, 403, 404].includes(err.status)) {
        ctx.log(`registrar: not available (HTTP ${err.status}; add Registrar: Domains Read to enable); skipping`);
        return undefined;
      }
      throw err;
    }
    for (const r of env.result ?? []) out.set(r.domain_name.toLowerCase(), r);
    cursor = env.result_info?.cursor ?? "";
    if (!cursor) break;
  }
  return out;
}

export interface DomainsDeps {
  /** Replaces RDAP/WHOIS lookups (tests). */
  lookup?: Lookup;
  fetchImpl?: typeof fetch;
}

export const createDomainsCollector = (deps: DomainsDeps = {}): Collector => ({
  id: "domains",
  label: "Domains",
  schedules: ["daily"],

  async collect(ctx) {
    const fetchImpl = deps.fetchImpl ?? ((i: RequestInfo | URL, init?: RequestInit) => fetch(i, init));
    const { cf, config, now } = ctx;
    const prev = (ctx.previousState as DomainsState | undefined) ?? { domains: {} };
    const date = now.toISOString().slice(0, 10);

    // All statuses (not just active), so "moved"/"pending" zones are seen.
    const zones = filterZones(await cf.getAllPages<ApiZone>(`/zones?account.id=${encodeURIComponent(ctx.env.CF_ACCOUNT_ID)}`, 50, 4), config);

    const registrations = await listRegistrations(ctx);

    // Registry lookups. The IANA RDAP bootstrap is cached for 30 days.
    let rdap = prev.rdap;
    let lookup: Lookup | undefined;
    if (config.registryLookups) {
      if (!rdap || now.getTime() - rdap.fetchedAt > BOOTSTRAP_TTL_MS) {
        try {
          const res = await fetchImpl(BOOTSTRAP_URL, { signal: AbortSignal.timeout(LOOKUP_TIMEOUT_MS) });
          const body = (await res.json()) as { services: [string[], string[]][] };
          const tlds = new Set(zones.map((z) => z.name.split(".").pop()!.toLowerCase()));
          rdap = { fetchedAt: now.getTime(), services: body.services.filter(([t]) => t.some((x) => tlds.has(x))) };
        } catch (err) {
          ctx.log(`rdap bootstrap failed: ${(err as Error).message}`);
        }
      }
      lookup = deps.lookup ?? (rdap ? makeLookup(rdap.services, fetchImpl) : undefined);
    }

    const findings: Finding[] = [];
    const state: DomainsState = { domains: {}, rdap };
    const stats: Record<string, CollectorStats> = {};
    let lookupFailures = 0;
    for (const zone of zones) {
      let dnssec: string | undefined;
      if (zone.status === "active" && cf.remaining > 6) {
        dnssec = await cf.get<{ status: string }>(`/zones/${zone.id}/dnssec`).then((r) => r.status).catch(() => undefined);
      }
      let registry: RegistryInfo | undefined;
      if (lookup) {
        try {
          registry = await lookup(zone.name);
        } catch (err) {
          lookupFailures++;
          ctx.log(`registry lookup failed for ${zone.name}: ${(err as Error).message}`);
        }
      }
      const r = analyseDomain(
        { zone, dnssec, registration: registrations?.get(zone.name.toLowerCase()), registry },
        prev.domains[zone.name],
        { now: now.getTime(), expiryWarnDays: config.domainExpiryWarnDays, date },
      );
      findings.push(...r.findings);
      state.domains[zone.name] = r.snapshot;
      stats[zone.name] = { registry: registry ? 1 : 0, registrar: registrations?.has(zone.name.toLowerCase()) ? 1 : 0 };
    }
    if (lookupFailures) stats["account"] = { registryLookupFailures: lookupFailures };
    return { findings, stats, newState: state };
  },
});

export const domains = createDomainsCollector();
