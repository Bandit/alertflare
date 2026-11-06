import { COLLECTORS } from "./collectors";
import { run } from "./pipeline";
import type { Env, Schedule } from "./types";

/**
 * Cron expressions (UTC) -> schedule. Must match wrangler.jsonc.
 * Cron Triggers only run in UTC; see README for daylight saving.
 */
export const CRONS: Record<string, Schedule> = {
  "0 19 * * *": "daily",
  "30 * * * *": "hourly",
};

export default {
  async scheduled(controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const schedule = CRONS[controller.cron];
    if (!schedule) {
      console.error(`unknown cron "${controller.cron}"`);
      return;
    }
    // Retrying a digest run could double-send; a missed run is caught up
    // by the next one (state diffing is idempotent).
    (controller as unknown as { noRetry?: () => void }).noRetry?.();
    const report = await run(env, schedule, new Date(controller.scheduledTime), {
      collectors: COLLECTORS,
      forceHeartbeat: env.FORCE_HEARTBEAT === "true",
    });
    console.log(
      JSON.stringify({
        schedule,
        reported: report.reported.length,
        failures: report.failures,
        subrequests: report.subrequests,
        sent: report.sent,
      }),
    );
  },

  // No HTTP interface on purpose: nothing to attack. (workers_dev is off.)
  async fetch(): Promise<Response> {
    return new Response("Not found", { status: 404 });
  },
} satisfies ExportedHandler<Env>;
