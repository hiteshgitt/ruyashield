// Downloads MaxMind GeoLite2-Country and GeoLite2-ASN with YOUR MaxMind account (free licence, accept their EULA first).
// Run by an operator, never automatically:
//   MAXMIND_ACCOUNT_ID=... MAXMIND_LICENSE_KEY=... npx tsx scripts/geoip-update.mts [target-dir]
// Each archive's SHA-256 is checked against MaxMind's published checksum before it is unpacked.
// Then set GEOIP_COUNTRY_DB_PATH and GEOIP_ASN_DB_PATH (see .env.example). Re-run weekly (e.g. from cron).
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const id = process.env.MAXMIND_ACCOUNT_ID?.trim(), key = process.env.MAXMIND_LICENSE_KEY?.trim();
if (!id || !key) { console.error("Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY."); process.exit(2); }
const dir = resolve(process.argv[2] ?? "data/geoip");
mkdirSync(dir, { recursive: true });
const auth = "Basic " + Buffer.from(`${id}:${key}`).toString("base64");
const MAX = 200 * 1024 * 1024;

async function get(url: string): Promise<Buffer> {
  const r = await fetch(url, { headers: { authorization: auth }, redirect: "follow", signal: AbortSignal.timeout(120_000) });
  if (r.status === 401) throw new Error("MaxMind rejected the account ID / licence key (401).");
  if (!r.ok) throw new Error(`MaxMind download failed: HTTP ${r.status}`);
  const b = Buffer.from(await r.arrayBuffer());
  if (b.length > MAX) throw new Error("download too large");
  return b;
}

for (const edition of ["GeoLite2-Country", "GeoLite2-ASN"]) {
  const base = `https://download.maxmind.com/geoip/databases/${edition}/download?suffix=`;
  const [tgz, sumFile] = await Promise.all([get(base + "tar.gz"), get(base + "tar.gz.sha256")]);
  const want = sumFile.toString("utf8").trim().split(/\s+/)[0]?.toLowerCase();
  const got = createHash("sha256").update(tgz).digest("hex");
  if (!want || want !== got) throw new Error(`${edition}: checksum mismatch, not installing`);
  const tmp = mkdtempSync(join(dir, ".tmp-"));
  try {
    writeFileSync(join(tmp, "db.tar.gz"), tgz);
    // Extract only the .mmdb file; no absolute paths or "..".
    execFileSync("tar", ["-xzf", join(tmp, "db.tar.gz"), "-C", tmp, "--no-same-owner", "--wildcards", "*/" + edition + ".mmdb"]);
    const sub = readdirSync(tmp, { withFileTypes: true }).find((d) => d.isDirectory() && d.name.startsWith(edition + "_"));
    if (!sub) throw new Error(`${edition}: unexpected archive layout`);
    renameSync(join(tmp, sub.name, `${edition}.mmdb`), join(dir, `${edition}.mmdb`)); // atomic swap; readers reload
    console.log(`${edition}: installed ${join(dir, edition + ".mmdb")}`);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
}
