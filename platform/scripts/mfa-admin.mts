// Operator tool for authenticator problems. Run on the server with the production environment loaded:
//   sudo bash -c 'set -a; . /etc/ruyashield/env; set +a; cd /srv/ruyashield/app && \
//     setpriv --reuid=ruya --regid=ruya --init-groups -- node node_modules/tsx/dist/cli.mjs scripts/mfa-admin.mts <command> <email>'
// Commands:
//   recovery <email>  new recovery codes, shown once the next time the user opens /auth/mfa (within 15 minutes)
//   reset <email>     lost phone: removes the authenticator and signs the user out; they set it up again at next sign-in
import { eq } from "drizzle-orm";
import { db, withOrg } from "../src/server/db/client";
import { users } from "../src/server/db/schema";
import { audit } from "../src/server/audit/audit";
import { issueRecoveryReveal, resetMfa } from "../src/server/auth/mfa";

const [cmd, email] = process.argv.slice(2);
if (!["recovery", "reset"].includes(cmd ?? "") || !email) {
  console.error("usage: mfa-admin.mts recovery|reset <email>");
  process.exit(2);
}
const u = (await db.select().from(users).where(eq(users.email, email.toLowerCase())))[0];
if (!u) { console.error(`no user with email ${email}`); process.exit(1); }
if (cmd === "recovery") {
  await issueRecoveryReveal(u.id, "/");
  console.log(`New recovery codes for ${u.email}. They see them at /auth/mfa within 15 minutes; old codes no longer work.`);
} else {
  await resetMfa(u.id);
  console.log(`Authenticator removed for ${u.email} and their sessions ended. They set it up again at next sign-in.`);
}
await withOrg(null, (tx) => audit(tx, { actor: { type: "service", id: "mfa-admin" }, action: `auth.mfa_admin_${cmd}`, target: { type: "user", id: u.id } }));
process.exit(0);
