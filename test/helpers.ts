import { loadConfig } from "../src/config";
import type { Env } from "../src/types";

export class MemoryKV {
  store = new Map<string, string>();
  puts = 0;
  async get(key: string, type?: string) {
    const v = this.store.get(key);
    if (v === undefined) return null;
    return type === "json" ? JSON.parse(v) : v;
  }
  async put(key: string, value: string) {
    this.puts++;
    this.store.set(key, value);
  }
  async delete(key: string) {
    this.store.delete(key);
  }
}

export function testEnv(overrides: Record<string, string> = {}): Env {
  return {
    ALERTFLARE_STATE: new MemoryKV() as unknown as KVNamespace,
    CF_API_TOKEN: "test-token",
    CF_ACCOUNT_ID: "acc",
    DRY_RUN: "true",
    ...overrides,
  } as Env;
}

export const testConfig = (o: Record<string, string> = {}) => loadConfig(testEnv(o));

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}
