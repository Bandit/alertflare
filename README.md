# alertflare

A Cloudflare Worker that emails a **low-noise digest** of interesting activity
across a whole Cloudflare account. It covers:

- blocked integrations, such as a webhook silently stopped by a WAF rule;
- configuration changes;
- new API tokens and logins from new IPs;
- denied Access logins;
- DNS and SSL drift.

It stays quiet about the constant background noise of internet scanners. If
nothing new happened, it sends **nothing**. A weekly heartbeat proves it is
still alive.

- Daily digest: at the hour you set in the daily cron (see §3), grouped by severity and then by zone.
- Hourly urgent check: API tokens, account members, failed logins and logins
  from new IPs. It sends only when something new happens and never repeats
  an item.
- Weekly heartbeat on Monday: totals per collector and per zone, plus any
  collector failures.

## 1. What runs here vs. what Cloudflare already does

Facts were checked against developers.cloudflare.com in November 2026.

### Enable these native Notifications instead

Go to Dashboard → Notifications → Add. Every notification here is available
on Free and Pro, and can be delivered by email or webhook.

| Notification | Why |
|---|---|
| **Tunnel Health Alert** | Fires on tunnel state changes (healthy, degraded, down, inactive) on all Zero Trust plans. alertflare therefore does **not** poll tunnels. |
| **Tunnel Creation or Deletion Event** | Instant alert when a tunnel is created or deleted. |
| **HTTP DDoS Attack Alert** | Fires on attacks mitigated above 100 rps, on all plans. |
| **Universal SSL Alert** | Covers certificate validation, issuance, renewal and expiry. |
| **Health Checks status** *(Pro+)* | If you configure a Health Check on your origin, this is the best way to learn the origin itself is down. |
| **Expiring Access Service Token** *(if you use service tokens)* | |
| **Incident Alerts** *(optional)* | Cloudflare status incidents. Useful context when your alerts fire. |

These are **not** available natively on Free or Pro, so alertflare covers them:

- WAF and security event alerts. Native Security Events Alerts need Business or higher.
- Audit-log, API-token, member and login alerts. No native notification exists.
- DNS and zone change alerts. No native notification exists outside Secondary DNS.
- Alerts that a Worker or cron stopped running. No native notification exists,
  which is why the heartbeat is built in.

### Collectors

| Collector | Schedule | Data source | Free | Pro |
|---|---|---|---|---|
| `security-events` | daily | GraphQL `firewallEventsAdaptive*` | ✅ raw sampled events, up to 1,000 per zone | ✅ server-side aggregation (`firewallEventsAdaptiveGroups`) |
| `audit-logs` | daily + hourly (urgent only) | Audit Logs **v2** `GET /accounts/{id}/logs/audit` (GA since 2026‑03; all plans; 18-month retention) | ✅ | ✅ |
| `access` | daily | `GET /accounts/{id}/access/logs/access_requests` | ✅ (Zero Trust Free keeps only **24 h** of logs) | ✅ |
| `inventory` | daily | `GET /zones/{id}/dns_records`, `GET /zones/{id}/settings/ssl` | ✅ | ✅ |
| ~~tunnel health~~ | | | Use the native Tunnel Health Alert | |

Account-level security analytics needs Enterprise, so `security-events`
enumerates zones and queries them in batches of up to 10 zones per GraphQL
query. That batch size is the documented per-query limit.

## 2. Setup

```bash
npm install
```

### 2.1 Create the API token (read-only, minimum permissions)

Go to Dashboard → My Profile → API Tokens → **Create Token** → *Create Custom Token*.

| Scope | Permission | Access | Needed by | Why |
|---|---|---|---|---|
| Account | **Account Analytics** | Read | security-events | Required by the GraphQL Analytics API, per the docs page "Configure an Analytics API token". |
| Account | **Account Settings** | Read | audit-logs | Required by both v1 and v2 audit log endpoints. |
| Account | **Access: Audit Logs** | Read | access | Access authentication logs. Omit it if you don't use Access, and add `access` to `DISABLED_COLLECTORS`. |
| Zone | **Zone** | Read | all | Lists the zones in the account. |
| Zone | **DNS** | Read | inventory | Reads DNS records to detect new hostnames and proxied flips. |
| Zone | **Zone Settings** | Read | inventory | Reads the SSL/TLS mode. |

- **Account Resources:** *Include → your account* only.
- **Zone Resources:** *Include → All zones from an account → your account*.
- **Not needed:** any Edit/Write permission, Cloudflare Tunnel Read (no tunnel
  collector), and Zone Analytics Read.
- If the GraphQL queries return a permission error on your account, add
  *Zone → Analytics → Read*. The docs only name the Account-level permission.

Store the token as a secret. Never put it in `wrangler.jsonc` or `.dev.vars.example`.

```bash
npx wrangler secret put CF_API_TOKEN
```

```bash
npx wrangler secret put CF_ACCOUNT_ID
```

`CF_ACCOUNT_ID` is optional. Without it, alertflare discovers the account from
the token, which costs one extra API call per run.

### 2.2 KV namespace

```bash
npx wrangler kv namespace create alertflare-state
```

Paste the returned `id` into `wrangler.jsonc`, replacing `REPLACE_WITH_KV_NAMESPACE_ID`.

In the dashboard (Storage & Databases → KV), the namespace appears as `alertflare-state`.
The code reaches it through the binding `ALERTFLARE_STATE`. Deleting the namespace is safe:
current findings are reported once more and baselines are learned again.

### 2.3 Email

The sender sits behind the `Notifier` interface in `src/notify/notifier.ts`.
Choose one with the `NOTIFIER` var.

**Postmark** (`NOTIFIER=postmark`, the default in `wrangler.jsonc`):

```bash
npx wrangler secret put POSTMARK_SERVER_TOKEN
```

```bash
npx wrangler secret put EMAIL_FROM
```

```bash
npx wrangler secret put EMAIL_TO
```

- `EMAIL_FROM` must be a confirmed Postmark Sender Signature or on a verified domain.
- `EMAIL_TO` takes a comma-separated list.
- Sends go to the `outbound` (transactional) stream. Override this with `POSTMARK_MESSAGE_STREAM`.

**Cloudflare Email Service** (`NOTIFIER=cloudflare`) uses the `send_email`
binding that is already declared in `wrangler.jsonc`.

- Enable Email Routing on one of your zones.
- `EMAIL_FROM` must be an address on that routing domain.
- `EMAIL_TO` must be a **verified destination address**. Sending to verified
  addresses is free on all plans.
- Messages sent this way show as "dropped" in the Email Routing summary even
  though they were delivered. Cloudflare documents this as known behaviour.

### 2.4 Deploy

`DRY_RUN` is `"true"` in `wrangler.jsonc`, so the first deploy only logs
digests. Check `npx wrangler tail` or Workers Observability, then set
`DRY_RUN` to `"false"` and deploy again.

```bash
npm run deploy
```

The Worker has no public URL (`workers_dev: false`) and its `fetch` handler
returns 404, so there is no HTTP endpoint to attack.

## 3. Schedules and daylight saving

Cron Triggers run in **UTC only**. Cloudflare has no timezone support.

| Cron (UTC) | Purpose |
|---|---|
| `0 19 * * *` | daily digest (plus the heartbeat on `HEARTBEAT_DAY`) |
| `30 * * * *` | hourly urgent check |

- Pick the daily cron hour so the digest arrives when you want it in your
  local time, for example `0 7 * * *` for 08:00 in UTC+1.
- If your timezone has daylight saving, local delivery shifts by an hour
  twice a year. Accept that, or change the cron at each switch. Change it in
  **both** `wrangler.jsonc` and `CRONS` in `src/index.ts`.
- Dates in messages and the heartbeat weekday use `TIMEZONE` (default `UTC`).

## 4. Run locally

```bash
cp .dev.vars.example .dev.vars
```

Fill in `.dev.vars` with a real read-only token and keep `DRY_RUN=true`. Then
start the dev server:

```bash
npm run dev
```

In another terminal, trigger each schedule:

```bash
curl "http://localhost:8787/__scheduled?cron=0+19+*+*+*"
```

```bash
curl "http://localhost:8787/__scheduled?cron=30+*+*+*+*"
```

- The digest is printed to the `wrangler dev` console between
  `----- DRY RUN -----` markers.
- Local KV state persists in `.wrangler/state`. Delete that folder to start fresh.
- To force the weekly heartbeat, add `FORCE_HEARTBEAT=true` to `.dev.vars`.

Run the tests (Vitest, with fixtures shaped like real API responses) and the type check:

```bash
npm test
```

```bash
npm run typecheck
```

## 5. Configuration (`vars` in `wrangler.jsonc`)

| Var | Default | Meaning |
|---|---|---|
| `DRY_RUN` | `true` | Log the digest instead of sending it. |
| `NOTIFIER` | `postmark` if `POSTMARK_SERVER_TOKEN` is set, otherwise `cloudflare` | Which sender to use. |
| `TIMEZONE` | `UTC` | IANA timezone for dates in messages and for picking the heartbeat day, e.g. `Europe/London`. Set it as a secret (`wrangler secret put TIMEZONE`) if you'd rather not commit your location. |
| `HEARTBEAT_DAY` | `mon` | Local weekday for the heartbeat. |
| `INTERESTING_PATHS` | `/api/*` | Blocked requests to these paths are always reported, as `warning`. |
| `INTERESTING_METHODS` | `POST,PUT,PATCH,DELETE` | Blocked requests with these methods are always reported, as `warning`. |
| `ASN_REPEAT_THRESHOLD` | `50` | Hits per day on one fingerprint (which includes the ASN) before an otherwise ordinary block is reported, as `info`. |
| `VOLUME_JUMP_MULTIPLIER` | `3` | Re-report a known fingerprint when its daily count is at least this multiple of the count at its last report… |
| `VOLUME_JUMP_MIN_COUNT` | `20` | …and is at least this many hits. |
| `FORGET_AFTER_DAYS` | `30` | Forget a fingerprint unseen for this long, so a recurrence is reported again. |
| `IGNORE_PATHS` | *(built-in list)* | Replaces the built-in scanner ignore list. |
| `EXTRA_IGNORE_PATHS` | | Adds entries to the built-in list. |
| `ZONES_INCLUDE` / `ZONES_EXCLUDE` | | Comma-separated zone names. |
| `DISABLED_COLLECTORS` | | For example `access`. |
| `MAX_ZONES_PER_RUN` | `10` | Inventory zones checked per daily run. Zones rotate (see §8). |

## 6. Noise rules

Security events are grouped into **fingerprints** made of:

- zone and host;
- the security service and rule ID;
- the HTTP method;
- the **normalised path**;
- the source ASN.

Normalisation collapses UUIDs, hex strings, numbers and random-looking
tokens. For example, `/api/webhook/3f9a12bc…e8` becomes
`/api/webhook/{id}`, so one integration produces exactly one fingerprint.

Each fingerprint gets one of three verdicts:

- **Noise:** the path matches the ignore list. It is never alerted, only
  counted in the heartbeat. Most of this noise is also filtered out
  server-side, with `_notlike` filters, to save rows.
- **Interesting:** the path matches `INTERESTING_PATHS`, the method matches
  `INTERESTING_METHODS`, or the count is at least `ASN_REPEAT_THRESHOLD`.
- **Boring:** everything else. It is counted only.

Only these actions count as mitigations: block, challenge, JS challenge,
managed challenge and connection close. Solved challenges, `log`, `skip`,
`allow` and `bypass` are excluded.

**Built-in ignore list.** These globs are case-insensitive, and `*` matches
across `/`. See `DEFAULT_IGNORE_PATHS` in `src/config.ts`.

```
/wp-*  */wp-admin*  */wp-includes*  */wp-content*  */wp-login*  */xmlrpc.php*
*.php  *.php7  *.asp  *.aspx  *.jsp  *.cgi  /cgi-bin/*
*/.env*  */.git/*  */.git  */.svn/*  */.hg/*  */.ds_store  */.aws/*  */.ssh/*  */.vscode/*  */.idea/*
/phpmyadmin*  /pma*  /myadmin*  /admin.php*  /boaform/*  /actuator*  /vendor/phpunit*
/owa/*  /ecp/*  /autodiscover*  /remote/login*  /geoserver*  /solr/*  /hnap1*  /sdk  /shell*  /console*
/server-status*  /config.json  /config.js  /backup*  *.sql  *.bak  *.zip  *.tar.gz
/robots.txt  /sitemap.xml  /favicon.ico  /ads.txt  /security.txt  /.well-known/security.txt
```

**Audit logs:**

- Every non-`view` change is reported once.
- These are `urgent` and are also sent by the hourly check:
  - creating or changing an API token;
  - member or role changes;
  - failed logins;
  - logins from an IP not seen before for that user.
- `warning`: changes to WAF, rulesets, Access and tunnels.
- `info`: everything else.
- The first run learns your login IPs silently.
- The audit API has no country field, so new-country detection isn't possible.
  New IP is the signal used instead.

**Access:** denied logins are grouped by application, identity and country.
A group with 10 or more denials becomes `warning`.

**Inventory:**

- Reported: new or removed DNS records, proxied ↔ DNS-only flips, SSL/TLS mode
  changes, and zones added or removed.
- DNS-only A, AAAA or CNAME records, and SSL dropping to `off` or `flexible`,
  are `warning`.
- The first run takes a baseline silently.
- Record contents, such as origin IPs, are never stored or sent.

## 7. Acknowledging and resetting

"Already reported" state lives in KV. There is one JSON document per
collector, `reported:<collector>`, which keeps writes inside the Free tier's
1,000 per day. The `ack` script runs against **production** KV by default; add
`--local` to use `wrangler dev` storage instead.

List what a collector has already reported:

```bash
npm run ack -- list security-events
```

Acknowledge a fingerprint. It will never be re-reported, even if its volume jumps.

```bash
npm run ack -- ack security-events /api/webhook/{id}
```

Undo an acknowledgement:

```bash
npm run ack -- unack security-events /api/webhook/{id}
```

Forget a fingerprint, so it is reported again on the next run if it is still happening:

```bash
npm run ack -- forget audit-logs some-id
```

Reset a collector completely, so everything current is reported again:

```bash
npx wrangler kv key delete reported:security-events --binding ALERTFLARE_STATE --remote
```

Reset the inventory or login-IP baseline:

```bash
npx wrangler kv key delete state:inventory --binding ALERTFLARE_STATE --remote
```

The fix for the broken-webhook problem is usually a WAF exception, not an
acknowledgement. Once the exception is fixed the blocks stop, the fingerprint
stops appearing, and it is forgotten after `FORGET_AFTER_DAYS`.

## 8. Limits (Workers Free) and scaling

These limits were checked against developers.cloudflare.com in November 2026.

| Limit (Free) | Value | How alertflare stays inside it |
|---|---|---|
| Subrequests per invocation | 50 | Cloudflare API calls are capped at 47 per run by a shared budget. The rest is kept for Postmark sends: digest plus heartbeat. |
| CPU per Cron invocation | **10 ms** (network wait doesn't count) | GraphQL aggregates server-side where the plan allows. Raw mode is capped at 1,000 rows per zone and filters noise server-side. The pipeline is a single pass. |
| Cron Triggers per account | 5 | Uses 2. |
| KV writes per day | 1,000 | One document per collector, written only when it changed: roughly 10 writes per day plus at most 2 per hourly run. |
| GraphQL | 300 queries per 5 min; 10 zones per query | 2–3 queries per 10 zones per day. |

API calls per daily run, with N zones:

| Collector | Calls |
|---|---|
| Zones list | 1 |
| Audit logs | 1–3 |
| Access | 1 |
| Security events | about 1 per 10 zones, plus 1 per 10 zones for the weekly capability check |
| Inventory | 2 per zone, for up to `MAX_ZONES_PER_RUN` zones |

- **Up to about 15 zones**, everything fits in one invocation and every zone is
  fully checked every day.
- **With more zones:**
  - Security events still covers every zone daily (10 zones per query).
  - Inventory **rotates**, checking `MAX_ZONES_PER_RUN` zones per day and
    continuing where it left off. It also never uses the last few
    subrequests. If the budget runs out mid-run, the affected collector reports
    one short "ran out of subrequest budget" finding and the others still
    report.
  - Fixes, in order of preference:
    1. Lower `MAX_ZONES_PER_RUN`. Inventory then takes longer to cycle through.
    2. Move inventory to its own cron (for example `0 18 * * *`). Each cron
       invocation gets its own 50-subrequest budget, and you have 3 spare
       triggers. This needs a third schedule name in `src/index.ts`.
    3. Workers Paid ($5/month) raises the limits to 10,000 subrequests and 30 s
       CPU.
- **CPU on Free:** a zone with very heavy blocked traffic in **raw mode**
  (Free-plan zones) parses up to 1,000 events. That is usually well under
  10 ms, but if you see `exceededCpu` in the logs, add the noisy paths to
  `EXTRA_IGNORE_PATHS` (they are filtered server-side) or move to Paid.
  Pro zones use server-side aggregation and aren't affected.

## 9. Data caveats

- **Sampling.** Firewall event datasets are adaptively sampled. Counts are
  sample-weighted estimates (`count` / `sampleInterval`), and Ray IDs are
  examples.
- **Retention.** Security events are kept for 31 days on all plans. Access logs
  on Zero Trust Free are kept for only 24 hours, so a missed daily run loses
  that window. Audit logs are kept for 18 months.
- **Unverified in the docs; confirm on your account.** The exact GraphQL
  `action` spellings aren't documented, so alertflare matches patterns instead
  of hard-coding them. The error that means "Access isn't set up" isn't
  documented either; alertflare treats a 404 or a "not enabled" message as
  "skip" and anything else as a failure. Whether audit logs v2 records ordinary
  dashboard logins isn't confirmed. The first `DRY_RUN` against your real
  account settles all three.

## 10. Privacy in notifications

- Webhook IDs and other token-like path segments are cut to their first 8
  characters, for example `3f9a12bc…`. Query strings are dropped.
- Audit request and response bodies are never read into messages. They can
  contain new token values.
- Text that looks like `Authorization`, `Cookie` or `Bearer` values is redacted.
- Dashboard links use `dash.cloudflare.com/?to=/:account/<zone-name>/…`, so they
  contain no account or zone IDs.
- Error messages replace IDs in API paths with `…`, and no stack traces are sent.

## 11. Adding a collector

Create `src/collectors/<name>.ts` that exports a `Collector`:

- `id`, `label` and `schedules`;
- `collect(ctx)`, returning `{ findings, stats, newState }`.

Then add it to `COLLECTORS` in `src/collectors/index.ts`.

The pipeline provides the rest:

- the shared API client and subrequest budget;
- per-collector KV state (`ctx.previousState` / `newState`);
- dedupe and volume-jump detection;
- failure isolation;
- the digest and the heartbeat.

Give each finding a stable `fingerprint` with no timestamps, unless you want a
dated one-off. Set `kind: "event"` for things that should only ever be reported
once.
