import type { Config } from "../config";
import type { ZoneRef } from "../types";
import type { CloudflareClient } from "./client";

interface ApiZone {
  id: string;
  name: string;
  status: string;
  plan?: { name?: string };
}

interface ApiAccount {
  id: string;
  name: string;
}

/**
 * Use CF_ACCOUNT_ID if set (recommended: saves a subrequest per run),
 * otherwise discover it from the token. Fails if the token can see more
 * than one account, because guessing would be unsafe.
 */
export async function resolveAccountId(cf: CloudflareClient, configured?: string): Promise<string> {
  if (configured && configured.trim()) return configured.trim();
  const accounts = await cf.get<ApiAccount[]>("/accounts?per_page=5");
  if (accounts.length === 1) return accounts[0]!.id;
  throw new Error(
    accounts.length === 0
      ? "token cannot see any account; set CF_ACCOUNT_ID"
      : "token can see several accounts; set CF_ACCOUNT_ID",
  );
}

/** GET /zones is limited to per_page 50; at most 4 pages (200 zones). */
export async function listZones(cf: CloudflareClient, accountId: string, config: Config): Promise<ZoneRef[]> {
  const raw = await cf.getAllPages<ApiZone>(`/zones?account.id=${encodeURIComponent(accountId)}&status=active`, 50, 4);
  return filterZones(
    raw.map((z) => ({ id: z.id, name: z.name, plan: z.plan?.name })),
    config,
  );
}

export function filterZones(zones: ZoneRef[], config: Pick<Config, "zoneInclude" | "zoneExclude">): ZoneRef[] {
  return zones
    .filter((z) => !config.zoneInclude.length || config.zoneInclude.includes(z.name.toLowerCase()))
    .filter((z) => !config.zoneExclude.includes(z.name.toLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Dashboard deep link that uses the zone *name* and the `:account`
 * placeholder, so notifications never carry account or zone IDs.
 */
export function dashLink(zoneName: string | undefined, path: string): string {
  return `https://dash.cloudflare.com/?to=/:account${zoneName ? `/${zoneName}` : ""}/${path}`;
}

export function chunk<T>(xs: T[], n: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n));
  return out;
}
