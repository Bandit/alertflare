import { describe, expect, it } from "vitest";
import { classifySegment, makeMatcher, normalisePath, redactPath, redactText } from "../src/lib/normalise";
import { DEFAULT_IGNORE_PATHS } from "../src/config";

const HA_WEBHOOK = "3f9a12bc0d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8";

describe("normalisePath", () => {
  it("collapses webhook ids so one integration = one fingerprint", () => {
    expect(normalisePath(`/api/webhook/${HA_WEBHOOK}`)).toBe("/api/webhook/{id}");
    expect(normalisePath("/api/webhook/0123456789abcdef0123456789abcdef")).toBe("/api/webhook/{id}");
  });
  it("collapses UUIDs, numbers and random tokens", () => {
    expect(normalisePath("/api/v1/items/12345")).toBe("/api/v1/items/{n}");
    expect(normalisePath("/u/f174be97-19b1-40d6-954d-70cd5fbd52db/x")).toBe("/u/{id}/x");
    expect(normalisePath("/cb/aZ3kQ9pL2mN8xR4tV7wY")).toBe("/cb/{id}");
    expect(normalisePath("/hook/vendor_a1b2c3d4e5f6g7h8")).toBe("/hook/{id}");
  });
  it("keeps ordinary words and short segments", () => {
    expect(normalisePath("/api/config/config_entries/flow")).toBe("/api/config/config_entries/flow");
    expect(normalisePath("/auth/authorize")).toBe("/auth/authorize");
    expect(normalisePath("/api/authorization-callback")).toBe("/api/authorization-callback");
    expect(classifySegment("v1")).toBe("plain");
    expect(classifySegment("2024")).toBe("num");
  });
  it("drops the query string and collapses slashes", () => {
    expect(normalisePath("//api//states?token=abc")).toBe("/api/states");
    expect(normalisePath("")).toBe("/");
  });
});

describe("redactPath", () => {
  it("truncates token-like segments to 8 chars", () => {
    expect(redactPath(`/api/webhook/${HA_WEBHOOK}`)).toBe("/api/webhook/3f9a12bc…");
    expect(redactPath("/api/states/123")).toBe("/api/states/123");
  });
  it("drops query strings (which may hold tokens)", () => {
    expect(redactPath("/auth?code=secretsecret")).toBe("/auth");
  });
});

describe("redactText", () => {
  it("removes bearer tokens, auth headers and long secrets", () => {
    const t = redactText("Authorization: Bearer abcDEF123.xyz cookie=session=1 and key 0123456789abcdef0123456789abcdef0123");
    expect(t).not.toContain("abcDEF123");
    expect(t).not.toContain("session=1");
    expect(t).toContain("01234567…");
  });
});

describe("ignore list matcher", () => {
  const isNoise = makeMatcher(DEFAULT_IGNORE_PATHS);
  it.each(["/wp-login.php", "/WP-ADMIN/", "/blog/wp-includes/x.js", "/.env", "/app/.env.production", "/.git/config", "/cgi-bin/luci", "/index.php", "/phpmyadmin/"])(
    "treats %s as noise",
    (p) => expect(isNoise(p)).toBe(true),
  );
  it.each(["/api/webhook/abc", "/", "/auth/authorize", "/api/states", "/local/env-card.js"])("does not treat %s as noise", (p) =>
    expect(isNoise(p)).toBe(false),
  );
});
