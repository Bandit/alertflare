import { describe, expect, it } from "vitest";
import { PostmarkNotifier } from "../src/notify/notifier";
import { makeNotifier } from "../src/pipeline";
import { loadConfig } from "../src/config";
import { jsonResponse, testEnv } from "./helpers";

describe("PostmarkNotifier", () => {
  it("posts to the Postmark email API", async () => {
    let req: { url: string; init?: RequestInit } | undefined;
    const n = new PostmarkNotifier("pm-token", "alerts@example.test", ["a@example.test", "b@example.test"], "outbound", async (url, init) => {
      req = { url, init };
      return jsonResponse({ ErrorCode: 0, Message: "OK", MessageID: "x" });
    });
    await n.send({ subject: "S", text: "T" });
    expect(req!.url).toBe("https://api.postmarkapp.com/email");
    expect((req!.init!.headers as Record<string, string>)["X-Postmark-Server-Token"]).toBe("pm-token");
    expect(JSON.parse(String(req!.init!.body))).toMatchObject({ From: "alerts@example.test", To: "a@example.test,b@example.test", Subject: "S", TextBody: "T", MessageStream: "outbound" });
  });
  it("reports Postmark errors without leaking the token", async () => {
    const n = new PostmarkNotifier("pm-secret-token", "f@x.test", ["t@x.test"], "outbound", async () =>
      jsonResponse({ ErrorCode: 400, Message: "Sender signature not confirmed" }, 422));
    await expect(n.send({ subject: "S", text: "T" })).rejects.toThrow(/422 ErrorCode 400 Sender signature not confirmed/);
    await expect(n.send({ subject: "S", text: "T" })).rejects.not.toThrow(/pm-secret-token/);
  });
});

describe("notifier selection", () => {
  const base = { DRY_RUN: "false", EMAIL_FROM: "f@x.test", EMAIL_TO: "t@x.test" };
  it("uses Postmark when its token is set", () => {
    const env = testEnv({ ...base, POSTMARK_SERVER_TOKEN: "t" });
    expect(makeNotifier(env, loadConfig(env))).toBeInstanceOf(PostmarkNotifier);
  });
  it("can be forced to the Cloudflare binding", () => {
    const env = testEnv({ ...base, POSTMARK_SERVER_TOKEN: "t", NOTIFIER: "cloudflare" });
    expect(() => makeNotifier(env, loadConfig(env))).toThrow(/send_email binding missing/);
  });
});
