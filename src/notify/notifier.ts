/** A rendered message, independent of transport. */
export interface Message {
  subject: string;
  text: string;
  html?: string;
}

/** Swap this out to send via Slack/ntfy/Pushover/etc. */
export interface Notifier {
  send(msg: Message): Promise<void>;
}

/** DRY_RUN: logs the message instead of sending it. */
export class ConsoleNotifier implements Notifier {
  async send(msg: Message): Promise<void> {
    console.log(`----- DRY RUN: ${msg.subject} -----\n${msg.text}\n----- end -----`);
  }
}

/**
 * Cloudflare Email Service `send_email` binding (structured builder API).
 * Without an onboarded sending domain, `to` must be a verified Email Routing
 * destination address and `from` must be on a domain with Email Routing.
 */
export class EmailNotifier implements Notifier {
  constructor(
    private binding: SendEmail,
    private from: string,
    private to: string[],
  ) {}

  async send(msg: Message): Promise<void> {
    await this.binding.send({
      from: { email: this.from, name: "alertflare" },
      to: this.to,
      subject: msg.subject,
      text: msg.text,
      ...(msg.html ? { html: msg.html } : {}),
    });
  }
}

/**
 * Postmark (https://postmarkapp.com/developer/api/email-api).
 *   POST https://api.postmarkapp.com/email
 *   Header X-Postmark-Server-Token: <server API token>
 * `from` must be a confirmed Postmark sender signature or verified domain.
 * Counts as one external subrequest per message.
 */
export class PostmarkNotifier implements Notifier {
  constructor(
    private serverToken: string,
    private from: string,
    private to: string[],
    private messageStream = "outbound",
    private fetchImpl: (input: string, init?: RequestInit) => Promise<Response> = (i, init) => fetch(i, init),
  ) {}

  async send(msg: Message): Promise<void> {
    const res = await this.fetchImpl("https://api.postmarkapp.com/email", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-Postmark-Server-Token": this.serverToken,
      },
      body: JSON.stringify({
        From: this.from,
        To: this.to.join(","),
        Subject: msg.subject,
        TextBody: msg.text,
        ...(msg.html ? { HtmlBody: msg.html } : {}),
        MessageStream: this.messageStream,
        Tag: "alertflare",
      }),
    });
    if (!res.ok) {
      // Only Postmark's error code/message: never echo request headers.
      const body = (await res.json().catch(() => ({}))) as { ErrorCode?: number; Message?: string };
      throw new Error(`Postmark send failed: HTTP ${res.status} ErrorCode ${body.ErrorCode ?? "?"} ${body.Message ?? ""}`.trim());
    }
  }
}
