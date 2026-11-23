# AGENTS.md

Rules for AI agents (and humans) working in this repository. This repo is
**public**, and it monitors a real Cloudflare account. Nothing about that
account or the owner's setup may end up in the repo, in any file, test,
fixture, comment or commit message.

## Never commit real values

- No real zone names, hostnames, subdomains, IP addresses, account IDs, zone
  IDs, tunnel names or IDs, API token names or IDs, KV/R2/D1 contents, email
  addresses or secrets.
- **Don't copy from screenshots, logs, emails, dashboard output or live API
  responses into the repo.** That is how real names leak: a test written
  from a real incident keeps the incident's real names. Rewrite every value
  as a placeholder first.
- Placeholders to use:
  - domains: `example.test`, `example.com`, `example.org`; random-looking
    labels like `app-k3x9qw7vbn2mzp4rt8y.example.com`
  - IPs: documentation ranges `192.0.2.0/24`, `198.51.100.0/24`,
    `203.0.113.0/24`
  - tunnels: `tunnel-a`, `tunnel-b`, `app-tunnel`; IDs like
    `11111111-1111-4111-8111-111111111111`
  - Cloudflare IDs: `00000000000000000000000000000001`, `aaaaaaaa…`
  - people: `owner@example.test`, `stranger@example.org`
- The one deliberate exception is the KV namespace ID in `wrangler.jsonc`,
  which is useless without an API token for the account.

## Don't describe the owner's setup

Code, docs and tests should read as a generic tool. Don't name the specific
self-hosted apps, integrations, WAF rules or security choices of the account
being monitored, even as "examples". Prefer neutral wording ("your app", "a
webhook integration", "a WAF rule").

## The privacy check

A git hook blocks commits whose added lines or message contain a real value.

- `npm install` enables the hooks (`core.hooksPath = .githooks`).
- `npm run privacy:refresh` builds `.private-denylist.json` (gitignored) from
  the live account using the read-only token in `.dev.vars`. Its `extra` list
  holds setup terms to block; edit it by hand.
- `npm run privacy:check` scans every tracked file.
- Matches print the kind of value and a 1–2 character hint, never the value.

If the check fires, replace the value with a placeholder. Don't bypass it
with `--no-verify`, and don't loosen the denylist to get a commit through.

## Other conventions

- Read-only API token only; ask before `wrangler deploy` or creating any
  Cloudflare resource (KV namespaces, secrets, notifications).
- Verify Cloudflare datasets, endpoints and fields against current docs or
  the live API before relying on them, and say when something is unverified.
- `npm test` and `npm run typecheck` must pass before committing.
