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
- Hourly urgent check: API tokens and account members. It sends only when
  something new happens and never repeats an item.
- Weekly heartbeat on Monday: totals per collector and per zone, plus any
  collector failures.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Bandit/alertflare)

Using the button? Create the API token first (§2.1), then see
[Deploy with the button](#deploy-with-the-button).

## 1. What runs here vs. what Cloudflare already does

Facts were checked against developers.cloudflare.com in November 2026.

### Enable these native Notifications instead

"Free" and "Pro" here mean the **zone** plan (per domain), not Workers Paid.
Unless marked otherwise, every notification here is available on Free and Pro
zones, and can be delivered by email or webhook. Step-by-step setup is in
**§2.5**.

| Notification | Why |
|---|---|
| **Tunnel Health Alert** | Fires on tunnel state changes (healthy, degraded, down, inactive) on all Zero Trust plans. alertflare therefore does **not** poll tunnels. |
| **Tunnel Creation or Deletion Event** | Instant alert when a tunnel is created or deleted. |
| **HTTP DDoS Attack Alert** | Fires on attacks mitigated above 100 rps, on all plans. |
| **Universal SSL Alert** | Covers certificate validation, issuance, renewal and expiry. |
| **Health Checks status** *(Pro zone plan or higher)* | If you configure a Health Check on your origin, this is the best way to learn the origin itself is down. |
| **Expiring Access Service Token** *(if you use service tokens)* | |
| **Incident Alerts** *(optional)* | Cloudflare status incidents. Useful context when your alerts fire. |

These are **not** available natively on Free or Pro, so alertflare covers them:

- WAF and security event alerts. Native Security Events Alerts need Business or higher.
- Audit-log, API-token and member alerts. No native notification exists.
  (Dashboard logins aren't covered by either: they aren't in account audit
  logs. See §9.)
- DNS and zone change alerts. No native notification exists outside Secondary DNS.
- Alerts that a Worker or cron stopped running. No native notification exists,
  which is why the heartbeat is built in.

### Collectors

| Collector | Schedule | Data source | Free | Pro |
|---|---|---|---|---|
| `security-events` | daily | GraphQL `firewallEventsAdaptive*` | ✅ raw sampled events, up to 1,000 per zone | ✅ server-side aggregation (`firewallEventsAdaptiveGroups`) |
| `audit-logs` | daily + hourly (urgent only); dashboard logins are not in account audit logs (see §9) | Audit Logs **v2** `GET /accounts/{id}/logs/audit` (GA since 2026‑03; all plans; 18-month retention) | ✅ | ✅ |
| `login-activity` | daily + hourly (urgent bursts only) | GraphQL `httpRequestsAdaptiveGroups`: POSTs to `LOGIN_PATHS` that **reached the origin** | ✅ (no ASN on Free, so grouped by country; 31 days of history) | ✅ |
| `tokens` | daily + hourly (urgent only) | `GET /user/tokens` (metadata only) | ✅ | ✅ |
| `domains` | daily | `GET /zones` (all statuses), `GET /zones/{id}/dnssec`, `GET /accounts/{id}/registrar/registrations`, plus a public registry lookup per domain (RDAP, or WHOIS on TCP 43 for `.nz`) | ✅ | ✅ |
| `access` | daily | `GET /accounts/{id}/access/logs/access_requests` | ✅ (Zero Trust Free keeps only **24 h** of logs) | ✅ |
| `inventory` | daily | `GET /zones/{id}/dns_records`, `GET /zones/{id}/settings` (one call for all settings) | ✅ | ✅ |
| ~~tunnel health~~ | | | Use the native Tunnel Health Alert | |

Account-level security analytics needs Enterprise, so `security-events`
enumerates zones and queries them in batches of up to 10 zones per GraphQL
query. That batch size is the documented per-query limit.

## 2. Setup

### Deploy with the button

The **Deploy to Cloudflare** button above copies this repository into your
GitHub account and creates the Worker, its cron triggers and a new KV
namespace for its state in your Cloudflare account. It then asks for the
values below; each prompt has a short description.

1. **Before you click**, create the read-only API token (§2.1) and decide how
   to send email (§2.3).
2. **Secrets** it asks for: `CF_API_TOKEN`, `CF_ACCOUNT_ID` (optional),
   `POSTMARK_SERVER_TOKEN`, `EMAIL_FROM` and `EMAIL_TO`. If you use
   Cloudflare Email instead of Postmark, set `NOTIFIER` to `cloudflare` and
   enter `unused` for the Postmark token.
3. **Variables** worth changing: set `DRY_RUN` to `true` for a trial run
   that only logs digests, `TIMEZONE` to your IANA timezone, and the daily
   cron hour in `wrangler.jsonc` in your copy (§3). The other defaults are
   this repo's own tuning; see §5.
4. After it deploys, set up the native notifications (§2.5).

Later changes go through your copy of the repository: Cloudflare redeploys
on every push to it.

### Deploy by hand

```bash
npm install
```

### 2.1 Create the API token (read-only, minimum permissions)

Go to Dashboard → My Profile → API Tokens → **Create Token** → *Create Custom Token*.

| Scope | Permission | Access | Needed by | Why |
|---|---|---|---|---|
| Zone | **Analytics** | Read | security-events, login-activity | **Required** for zone-scoped GraphQL queries. Verified on a live account: without it, GraphQL returns "zones … are not authorized". |
| Account | **Account Analytics** | Read | security-events | The docs page "Configure an Analytics API token" names this one. It may not be needed when Zone Analytics Read is present; it is harmless and read-only. |
| Account | **Account Settings** | Read | audit-logs | Required by both v1 and v2 audit log endpoints. |
| Account | **Access: Audit Logs** | Read | access | Access authentication logs. Omit it if you don't use Access, and add `access` to `DISABLED_COLLECTORS`. |
| Zone | **Zone** | Read | all | Lists the zones in the account. |
| Zone | **DNS** | Read | inventory | Reads DNS records to detect new hostnames and proxied flips. |
| Zone | **Zone Settings** | Read | inventory | Reads the SSL/TLS mode, minimum TLS version, HSTS and Always Use HTTPS. |
| Account | **Registrar: Domains** | Read | domains | *Optional.* Expiry, auto-renew, transfer lock and status for domains registered at Cloudflare. Without it, that part is skipped. Don't tick *Admin*. |
| User | **API Tokens** | Read | tokens | *Optional.* Token metadata (names, permissions, status, expiry; never token values), so new or changed tokens are reported. Without it, the collector is skipped. Don't tick *Edit*. |

- **Account Resources:** *Include → your account* only.
- **Zone Resources:** *Include → All zones from an account → your account*.
- **User Resources** (only if you add API Tokens Read): your user.
- **Not needed:** any Edit/Write permission, Cloudflare Tunnel Read (there
  is no tunnel collector), or User Details Read (the user audit log it
  unlocks had no logins or token changes on a live account; see §9).

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

Put the returned `id` into `wrangler.jsonc`. In this repo it's already set to the
production namespace. It's committed on purpose: a namespace ID isn't a secret.

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

For a first trial, set `DRY_RUN` to `"true"` in `wrangler.jsonc` so the
deploy only logs digests. Check `npx wrangler tail` or Workers Observability,
then set it back to `"false"` and deploy again.

```bash
npm run deploy
```

The Worker has no public URL (`workers_dev: false`) and its `fetch` handler
returns 404, so there is no HTTP endpoint to attack.

### 2.5 Native Cloudflare notifications (set up alongside alertflare)

The split:
- **Cloudflare's native alerts** cover anything that's **down or broken right
  now**: tunnels, your origin, certificates and DDoS attacks.
  They fire within minutes.
- **alertflare** covers what native alerts can't see on Free or Pro, in a daily
  digest: blocked integrations, configuration changes, new API tokens, Access
  denials, and DNS or SSL drift.

All of these are set up in the dashboard, not in code. Go to
**dash.cloudflare.com → your account → Notifications → Add**, pick the
product and then the notification type, and add your email as the delivery
method. After saving, use **Test** on each one. That shows you what it looks
like and lets you mark it "not spam" if needed.

**1. Tunnel Health Alert (the important one)**
- Product: **Cloudflare Tunnel → Tunnel Health Alert**. No filters; it covers
  every tunnel in the account.
- Fires when a tunnel moves between Healthy, Degraded, Down and Inactive, and
  again when it recovers. This is why alertflare has no tunnel collector.

**2. Tunnel Creation or Deletion Event**
- Product: **Cloudflare Tunnel → Tunnel Creation or Deletion Event**.
- Gives an instant alert when any tunnel is created or deleted.

**3. HTTP DDoS Attack Alert**
- Product: **DDoS Protection → HTTP DDoS Attack Alert**. No filters; it covers
  all zones.
- Fires when Cloudflare mitigates an HTTP DDoS attack above 100 requests per
  second. alertflare would only show such an attack the next morning, as
  volume.

**4. Universal SSL Alert**
- Product: **SSL/TLS → Universal SSL Alert**.
- Covers certificate validation, issuance, renewal and expiry problems. A
  failed renewal would otherwise break HTTPS with no warning.

**5. Health Check on your origin (Pro zone plan or higher)**

> Health Checks need the zone on **Pro or higher**. A Workers Paid
> subscription doesn't count. On a Free zone, skip this step; the Tunnel
> Health Alert is the closest native substitute.

The Tunnel Health Alert only tells you whether the *tunnel* is up. It won't
notice your app crashing behind a healthy tunnel and returning 502s.
A Health Check covers that.

1. Create the check: open the zone → **Traffic → Health Checks → Create**.
   - Address: your app's public hostname, over HTTPS on port 443.
   - Path: a page that returns 200 without logging in, so the check
     needs no credentials.
   - Expected codes: `200`.
   - Check regions: the region nearest your origin.
2. Add the notification: **Notifications → Add → Health Checks → Health Checks
   status notification**. Select the health check and choose **Either**
   (unhealthy *and* recovered).
3. **Check your WAF rules let the probes through.** After 5–10 minutes,
   the check should show **Healthy**. If it's unhealthy with a 403, a WAF rule
   is blocking the probes: add an exception for the health check's user agent.
   alertflare will also report those blocks in the next digest.

**6. Optional**

| Notification | When it's worth it |
|---|---|
| **Access → Expiring Access Service Token** | Only if you use Access service tokens, for example for scripts or machine-to-machine access. |
| **Incident Alerts** | Cloudflare status incidents. Filter to major or critical impact, and to the components you use (Tunnel, Access, WAF, DNS), to keep it quiet. |
| **Security Insights** | Cloudflare's Security Center findings, such as exposed origin IPs. Overlaps a little with alertflare's DNS-only record checks, but sees different things. |

**Not available on Free or Pro (skip):**

| Notification | Needs |
|---|---|
| Security Events Alert | Business or higher |
| Origin Error Rate | Enterprise |
| Layer 3/4 DDoS | Magic Transit or BYOIP |
| PagerDuty delivery | Business or higher |

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
| `INTERESTING_PATHS` | `/api/*` (this repo's `wrangler.jsonc` sets `/api/*,/auth/*`) | Blocked requests to these paths are reported, as `warning`, once they reach `MIN_HITS`. `/auth/*` covers login flows that live outside `/api/`. |
| `INTERESTING_METHODS` | `POST,PUT,PATCH,DELETE` | Blocked requests with these methods are always reported, as `warning`. |
| `MIN_HITS` | `3` | Minimum hits per day before a path- or method-based match is reported. One-off scanner probes are 1–3 hits; a broken integration retries all day (about 90 a day). Set it to `1` if you have webhooks that fire only once a day. |
| `OWN_RULE_SOURCES` | `firewallCustom,firewallrules,ratelimit,ratelimitingrules,ip,iprange,asn,country,zonelockdown,uablock` | Security services whose rules *you* wrote. See §6. |
| `REDACT_HOSTNAMES` | `true` | Truncate random-looking hostname labels in emails, e.g. `app-k3x9….example.com`. |
| `ASN_REPEAT_THRESHOLD` | `50` | Hits per day on one fingerprint (which includes the ASN) before an otherwise ordinary block is reported, as `info`. |
| `VOLUME_JUMP_MULTIPLIER` | `3` | Re-report a known fingerprint when its daily count is at least this multiple of the count at its last report… |
| `VOLUME_JUMP_MIN_COUNT` | `20` | …and is at least this many hits. |
| `FORGET_AFTER_DAYS` | `30` | Forget a fingerprint unseen for this long, so a recurrence is reported again. |
| `IGNORE_PATHS` | *(built-in list)* | Replaces the built-in scanner ignore list. |
| `EXTRA_IGNORE_PATHS` | | Adds entries to the built-in list. |
| `ZONES_INCLUDE` / `ZONES_EXCLUDE` | | Comma-separated zone names. |
| `DISABLED_COLLECTORS` | | For example `access`. |
| `AUDIT_IGNORE` | *(built-in list)* | Replaces the list of audit entries to ignore. A plain entry is a case-insensitive substring match on the description; an entry containing `/` is a prefix match on `product/type` of the resource, e.g. `workers/observability.` for dashboard log queries. |
| `AUDIT_EXTRA_IGNORE` | | Adds to that list, for example `Upload Version,Create Worker Deployment` if Worker deploys are routine for you. |
| `AUDIT_INCLUDE_SYSTEM` | `false` | Include entries by `system` and `delegated_service` actors. |
| `LOGIN_PATHS` | `/auth/*` | Login endpoints watched by `login-activity` (POST only). The default suits apps whose login flow lives under `/auth/`. Set it to an empty string to disable the collector. |
| `LOGIN_BURST_THRESHOLD` | `30` | Login POSTs per hostname that count as unusual: per 24 h in the daily digest (`warning`, or `urgent` at 3×), per hour in the hourly check (`urgent`). Normal use is a handful a day. |
| `LOGIN_DISTINCT_IPS` | `10` | Distinct client IPs per hostname per 24 h that count as unusual. IPs are only counted, never stored or sent. |
| `LOGIN_HOME_COUNTRIES` | | Comma-separated country codes (e.g. `GB`) never reported as "new country". Leave empty to rely on what alertflare has learned. |
| `REGISTRY_LOOKUPS` | `true` | Look up each domain at its registry (RDAP or WHOIS) for the delegation (hijack) check. Sends only domain names, which are public, to the registries. |
| `DOMAIN_EXPIRY_WARN_DAYS` | `30` | Warn this many days before a domain expires when auto-renew isn't on (urgent within 7 days regardless). |
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
- **Interesting:** depends on who wrote the rule.
  - **Your own rules** (custom rules, rate limits, IP/ASN/country access rules;
    see `OWN_RULE_SOURCES`). A block here may be your rule catching
    legitimate traffic, which is the broken-webhook failure mode. Interesting when
    the path matches `INTERESTING_PATHS` **or** the method matches
    `INTERESTING_METHODS`, with at least `MIN_HITS` hits.
  - **Cloudflare's detections** (managed rulesets, bot features, …). A block
    here usually means an attack signature matched. Interesting only when the
    path **and** the method both match, with at least `MIN_HITS` hits. Exploit
    probes such as `POST /` matching a CVE signature are counted, not reported.
  - **Either kind,** when the count is at least `ASN_REPEAT_THRESHOLD`.
- **Boring:** everything else. It is counted only.

Severity:

| Severity | When |
|---|---|
| **urgent** | An interesting path, a write method **and** `ASN_REPEAT_THRESHOLD` hits: an integration retrying and being blocked all day. |
| **warning** | An interesting path or a write method. |
| **info** | Volume only. |

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
*../*  *..%2f*  */proc/self/*  */etc/passwd*  */win.ini*  /api/env  /api/.env*
```

**Audit logs:**

- **Ignored:** data-plane activity that the audit log records as "create"
  but which isn't configuration:
  - D1 queries
  - Analytics Engine SQL queries
  - R2 object uploads
  - Worker asset uploads

  Entries by `system` and `delegated_service` actors are ignored too. These are
  side effects of changes already logged for a person, such as DNS records
  created by Email Routing, certificate renewals and Wrangler's asset uploads.
  Set `AUDIT_IGNORE`, `AUDIT_EXTRA_IGNORE` or `AUDIT_INCLUDE_SYSTEM` to change
  this.
- Every other change is reported once. `info` items are **rolled up** into one
  line per actor and product, for example "you: 5 workers changes — Upload
  Version ×2, Create Worker Deployment ×2, …". Each daily run continues from
  where the previous one stopped, so nothing is counted twice.
- These are `urgent` and are also sent by the hourly check:
  - creating or changing an API token;
  - member or role changes.
- `warning`: changes to WAF, rulesets, Access and tunnels.
- `info`: everything else.
- Login detection (new IP, failed login) is implemented, but it never fires in
  practice, because account audit logs don't contain dashboard logins (see §9).

**Access:** denied logins are grouped by application, identity and country.
A group with 10 or more denials becomes `warning`.

**Inventory:**

- Reported: new or removed DNS records, proxied ↔ DNS-only flips, SSL/TLS mode
  changes, and zones added or removed.
- Edge certificate settings: minimum TLS version lowered, HSTS turned off, or
  Always Use HTTPS turned off are `warning`; the reverse (and HSTS max-age
  changes) are `info`. Like the SSL mode, only *changes* are reported, so a
  zone that was already weak when alertflare first saw it stays quiet.
- **New tunnel hostnames** (CNAMEs to `*.cfargotunnel.com`, either new or
  re-pointed) are a `warning`: "New tunnel hostname …: check your WAF rules cover it".
  WAF rules can't match "traffic going to a tunnel", so a rule meant
  only for tunnels must list their hostnames, for example
  `http.host in {"app.example.com" …}`. This reminder keeps that list complete.
  Only the hostname is stored, never the tunnel ID.
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
  "skip" and anything else as a failure.
- **Dashboard logins are not in account audit logs.** On a live account
  (November 2026), no login entries appeared in 30 days of the v1 API
  (`action.type=login`) or in the v2 API. Logins are user-level events, not
  account-level ones, so a token scoped to the account can't see them.

- **Login activity sees attempts, not outcomes.** Many apps answer a
  failed login with HTTP 200, so Cloudflare can't tell success from failure.
  `login-activity` reports *who is trying* (a country new to that hostname,
  or unusual volume or IP spread). Turn on the app's own
  failed-login protection, such as IP bans.
- **Only requests that reached an origin count.** Requests blocked at the
  edge are reported by `security-events` instead. Hostnames served by a
  Worker have no origin, so they are not covered by `login-activity`;
  tunnels and proxied origins are.
- **Baseline.** The first daily run learns the last 30 days of login
  countries per hostname silently; the hourly check waits for that baseline.
  A country unseen for 90 days is forgotten. A brand-new hostname has no
  history, so its first login (probably you) is reported once, unless the
  country is in `LOGIN_HOME_COUNTRIES`.

- **Token changes and the audit logs.** Creating or editing a user API token
  *does* appear in the account audit log ("Create Token" / "Update Token",
  resource scope `user`), which `audit-logs` reports as urgent. On a live
  account (November 2026) these entries appeared tens of minutes late. The
  `tokens` collector is an independent second check that also shows *what*
  changed (permissions gained or lost) and warns before tokens expire, so a
  single token change can produce one line from each. The user audit log
  (`/user/audit_logs`, needs User Details Read) had neither token changes nor
  dashboard logins, so alertflare doesn't use it.
- **Domains.** The registry lookup checks that the registry still delegates
  each domain to the nameservers Cloudflare assigned. A mismatch is reported
  as a possible hijack, even if nothing changed inside Cloudflare.
  `.nz` has no RDAP service, so `.nz` domains use WHOIS, which has no expiry
  date and no transfer lock; expiry for `.nz` comes only from the Registrar
  API, i.e. for domains registered at Cloudflare. Cloudflare's `.nz`
  registrations show **Key-Systems GmbH** as the registrar at the registry, so
  transferring a `.nz` domain to Cloudflare produces one expected
  "registrar changed" warning.

## 10. Privacy in notifications

- Webhook IDs and other token-like path segments are cut to their first 8
  characters, for example `3f9a12bc…`. Query strings are dropped.
- Random-looking hostname labels, such as an unguessable
  subdomain, are cut the same way (`REDACT_HOSTNAMES`). The full hostname is
  kept only in KV, as part of the fingerprint.
- Audit request and response bodies are never read into messages. They can
  contain new token values.
- Text that looks like `Authorization`, `Cookie` or `Bearer` values is redacted.
- Dashboard links use `dash.cloudflare.com/?to=/:account/<zone-name>/…`, so they
  contain no account or zone IDs.
- Error messages replace IDs in API paths with `…`, and no stack traces are sent.
- API tokens are described by name and permission names only. Token IDs,
  resource IDs and IP ranges in token conditions are stored only as hashes,
  and are never sent.

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
