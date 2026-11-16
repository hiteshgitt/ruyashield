// RS-WMON-004: prints referral funnel counts (all orgs, counts only). Run: npm run referral:funnel -- [days, default 30]
import { closeDb } from "../src/server/db/client";
import { referralFunnel } from "../src/server/webmonitor/referrals";

const days = Number(process.argv[2] ?? 30);
if (!Number.isInteger(days) || days < 1 || days > 365) {
  console.error("Usage: npm run referral:funnel -- <days 1-365>");
  process.exit(2);
}
const since = new Date(Date.now() - days * 86_400_000);
const f = await referralFunnel(since);
const pct = (n: number) => (f.received ? `${Math.round((n / f.received) * 100)}%` : "—");
console.log(`Referral funnel since ${since.toISOString().slice(0, 10)} (${days} days)`);
for (const k of ["received", "consented", "verified", "assessed", "converted"] as const) console.log(`  ${k.padEnd(10)} ${String(f[k]).padStart(6)}  ${pct(f[k])}`);
await closeDb();
