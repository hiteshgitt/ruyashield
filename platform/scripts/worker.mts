// Background worker: drains the outbox, schedules re-verification and regression re-tests, expires risk acceptances and approvals, observes opened changes. Run: npm run worker
import { closeDb } from "../src/server/db/client";
import { runOnce, scheduleReverifications } from "../src/server/worker/worker";
import { sweepAssessments } from "../src/server/assessments/assessments";
import { scheduleRiskExpiries } from "../src/server/findings/findings";
import { scheduleRegressions, sweepVerifications } from "../src/server/verification/verification";
import { sweepSandboxRuns } from "../src/server/remediation/plans";
import { observeOpenChanges, sweepExpiredApprovals } from "../src/server/remediation/approvals";
import { runRetention } from "../src/server/retention/retention";
import { log } from "../src/server/log";
import { pollAttackSources } from "../src/server/attacks/attacks";
import { geoip } from "../src/server/attacks/geoip";
import { sweepOrgPlans } from "../src/server/plans/lifecycle";

const POLL_MS = 2000, SCHEDULE_MS = 60_000, SWEEP_MS = 15_000, RETENTION_MS = 24 * 3_600_000, PLANS_MS = 5 * 60_000;
let stopping = false;
for (const s of ["SIGINT", "SIGTERM"] as const) process.on(s, () => { stopping = true; });

let lastSchedule = 0, lastSweep = 0, lastRetention = 0, lastPlans = 0;
log.info("worker.start", { pid: process.pid });
while (!stopping) {
  try {
    if (Date.now() - lastSchedule > SCHEDULE_MS) {
      lastSchedule = Date.now();
      const n = await scheduleReverifications();
      if (n) log.info("worker.scheduled_reverify", { count: n });
      const expired = await scheduleRiskExpiries();
      if (expired) log.info("worker.expired_risk_acceptances", { count: expired });
      const lapsed = await sweepExpiredApprovals();
      if (lapsed) log.info("worker.expired_approvals", { count: lapsed });
      const reg = await scheduleRegressions();
      if (reg.queued || reg.notRun) log.info("worker.scheduled_regressions", reg);
      const observed = await observeOpenChanges();
      if (observed) log.info("worker.observed_code_changes", { count: observed });
      try {
        const atk = await pollAttackSources(undefined, new Date(), (await geoip()).lookup);
        if (atk.polled) log.info("worker.attack_poll", { ...atk });
      } catch (e) {
        log.error("worker.attack_poll_error", { error: e instanceof Error ? e.message : String(e) });
      }
    }
    if (Date.now() - lastPlans > PLANS_MS) {
      lastPlans = Date.now();
      // Trials ending, trial reminders and Ruya Lab Pro on the creator's account.
      const p = await sweepOrgPlans();
      if (p.changed || p.reminded) log.info("worker.org_plans", p);
    }
    if (Date.now() - lastRetention > RETENTION_MS) {
      lastRetention = Date.now();
      const ret = await runRetention();
      if (ret.orgsPurged || ret.orgsDeleted) log.info("worker.retention", ret);
    }
    if (Date.now() - lastSweep > SWEEP_MS) {
      lastSweep = Date.now();
      const swept = await sweepAssessments();
      if (swept) log.info("worker.swept_assessments", { count: swept });
      const lost = await sweepVerifications();
      if (lost) log.info("worker.swept_verifications", { count: lost });
      const stuck = await sweepSandboxRuns();
      if (stuck) log.info("worker.swept_sandbox_runs", { count: stuck });
    }
    const n = await runOnce();
    if (n) continue;
  } catch (e) {
    log.error("worker.loop_error", { error: e instanceof Error ? e.message : String(e) });
  }
  await new Promise((r) => setTimeout(r, POLL_MS));
}
await closeDb();
log.info("worker.stop", {});
