import type { Collector } from "../types";
import { auditLogs } from "./auditLogs";
import { securityEvents } from "./securityEvents";
import { access } from "./access";
import { inventory } from "./inventory";
import { loginActivity } from "./loginActivity";
import { domains } from "./domains";
import { tokens } from "./tokens";
import { tunnels, tunnelSummary } from "./tunnels";

/**
 * Registered collectors, in run order. Order matters for the shared
 * subrequest budget: fixed-cost collectors first, inventory (which adapts
 * to whatever budget is left) last.
 *
 * To add a source: create a file exporting a `Collector`, add it here.
 *
 * Tunnel health replaces Cloudflare's native "Tunnel Health Alert", which
 * emails on every state flip: `tunnels` polls every 5 minutes and alerts
 * only on sustained outages; `tunnel-summary` rolls flapping into the digest.
 */
export const COLLECTORS: Collector[] = [tunnels, auditLogs, tokens, securityEvents, loginActivity, access, tunnelSummary, domains, inventory];
