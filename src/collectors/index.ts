import type { Collector } from "../types";
import { auditLogs } from "./auditLogs";
import { securityEvents } from "./securityEvents";
import { access } from "./access";
import { inventory } from "./inventory";
import { loginActivity } from "./loginActivity";
import { domains } from "./domains";
import { tokens } from "./tokens";

/**
 * Registered collectors, in run order. Order matters for the shared
 * subrequest budget: fixed-cost collectors first, inventory (which adapts
 * to whatever budget is left) last.
 *
 * To add a source: create a file exporting a `Collector`, add it here.
 *
 * Tunnel health is intentionally NOT a collector: Cloudflare's native
 * "Tunnel Health Alert" notification (all Zero Trust plans) already does
 * state-change alerting. See README.
 */
export const COLLECTORS: Collector[] = [auditLogs, tokens, securityEvents, loginActivity, access, domains, inventory];
