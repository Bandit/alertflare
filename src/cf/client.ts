/**
 * Minimal Cloudflare API client with a shared subrequest budget.
 *
 * Workers Free allows 50 external subrequests per invocation. Every collector
 * shares one client so the budget is enforced across the whole run; when it
 * runs out, BudgetExceededError is thrown and that collector fails cleanly
 * while the others still get their results reported.
 */

const API = "https://api.cloudflare.com/client/v4";

export class BudgetExceededError extends Error {
  constructor() {
    super("subrequest budget exhausted");
    this.name = "BudgetExceededError";
  }
}

export class CloudflareApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public codes: number[] = [],
  ) {
    super(message);
    this.name = "CloudflareApiError";
  }
}

interface V4Envelope<T> {
  success: boolean;
  errors?: { code: number; message: string }[];
  result: T;
  result_info?: { page?: number; per_page?: number; total_pages?: number; count?: number; total_count?: number; cursor?: string; cursors?: { after?: string } };
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export class CloudflareClient {
  public used = 0;

  constructor(
    private token: string,
    public budget = 45,
    private fetchImpl: FetchLike = (i, init) => fetch(i, init),
  ) {}

  get remaining(): number {
    return this.budget - this.used;
  }

  private async raw(path: string, init?: RequestInit): Promise<Response> {
    if (this.used >= this.budget) throw new BudgetExceededError();
    this.used++;
    return this.fetchImpl(path.startsWith("http") ? path : API + path, {
      ...init,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
  }

  /** GET a v4 endpoint and return the full envelope. */
  async getEnvelope<T>(path: string): Promise<V4Envelope<T>> {
    let res = await this.raw(path);
    // One retry for Cloudflare-side blips (5xx, e.g. "10500 Internal
    // authentication error"), if the budget allows.
    if (res.status >= 500 && this.remaining > 0) res = await this.raw(path);
    let body: V4Envelope<T>;
    try {
      body = (await res.json()) as V4Envelope<T>;
    } catch {
      throw new CloudflareApiError(`${shortPath(path)}: HTTP ${res.status} (non-JSON)`, res.status);
    }
    if (!res.ok || !body.success) {
      const errs = body.errors ?? [];
      const msg = errs.map((e) => `${e.code} ${e.message}`).join("; ") || `HTTP ${res.status}`;
      throw new CloudflareApiError(`${shortPath(path)}: ${msg}`, res.status, errs.map((e) => e.code));
    }
    return body;
  }

  async get<T>(path: string): Promise<T> {
    return (await this.getEnvelope<T>(path)).result;
  }

  /** Page-number pagination (`page`/`per_page`), bounded by maxPages. */
  async getAllPages<T>(path: string, perPage: number, maxPages = 5): Promise<T[]> {
    const out: T[] = [];
    for (let page = 1; page <= maxPages; page++) {
      const sep = path.includes("?") ? "&" : "?";
      const env = await this.getEnvelope<T[]>(`${path}${sep}page=${page}&per_page=${perPage}`);
      out.push(...(env.result ?? []));
      const total = env.result_info?.total_pages;
      if (!total || page >= total || (env.result ?? []).length < perPage) break;
    }
    return out;
  }

  async graphql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
    const res = await this.raw(`${API}/graphql`, {
      method: "POST",
      body: JSON.stringify({ query, variables }),
    });
    const body = (await res.json().catch(() => null)) as
      | { data?: T; errors?: { message: string; extensions?: { code?: string } }[] | null }
      | null;
    if (!res.ok || !body) throw new CloudflareApiError(`graphql: HTTP ${res.status}`, res.status);
    if (body.errors && body.errors.length) {
      throw new CloudflareApiError(`graphql: ${body.errors.map((e) => e.message).join("; ")}`, res.status);
    }
    if (!body.data) throw new CloudflareApiError("graphql: empty response", res.status);
    return body.data;
  }
}

/** Strip IDs from paths before they appear in error messages. */
export function shortPath(path: string): string {
  return path
    .replace(API, "")
    .split("?")[0]!
    .replace(/[0-9a-f]{32}/gi, "…");
}
