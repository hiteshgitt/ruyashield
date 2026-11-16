// Offline check of an exported FixProof JSON file (RS-FIXP-003): recomputes the SHA-256 of the record's canonical JSON.
// It proves the file is unchanged since RuyaShield wrote it; it says nothing about issues outside the re-tested checks.
// Run: npx tsx scripts/verify-fixproof.mts fixproof-xxxx-v1.json [previous-record.json]
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const sortKeys = (v: unknown): unknown =>
  Array.isArray(v) ? v.map(sortKeys)
    : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]))
      : v;
const hashOf = (record: unknown) => createHash("sha256").update(JSON.stringify(sortKeys(record))).digest("hex");

function load(path: string) {
  const doc = JSON.parse(readFileSync(path, "utf8")) as { format?: string; record?: Record<string, unknown>; sha256?: string };
  if (doc.format !== "ruyashield.fixproof/1" || !doc.record || typeof doc.sha256 !== "string") throw new Error(`${path}: not a RuyaShield FixProof export`);
  return { record: doc.record, sha256: doc.sha256 };
}

const [file, prevFile] = process.argv.slice(2);
if (!file) { console.error("usage: verify-fixproof.mts <export.json> [previous-export.json]"); process.exit(2); }
const x = load(file);
const actual = hashOf(x.record);
let ok = actual === x.sha256;
console.log(`record  ${x.record.id} v${x.record.version} status=${x.record.status}`);
console.log(`hash    ${ok ? "MATCH" : "MISMATCH"} (stated ${x.sha256}, computed ${actual})`);
if (prevFile) {
  const p = load(prevFile);
  const link = hashOf(p.record) === p.sha256 && x.record.prevSha256 === p.sha256;
  console.log(`chain   ${link ? "MATCH" : "MISMATCH"} (prevSha256 ${x.record.prevSha256 ?? "none"})`);
  ok &&= link;
} else {
  console.log(`chain   not checked (pass the previous record's export to check prevSha256 ${x.record.prevSha256 ?? "none"})`);
}
process.exit(ok ? 0 : 1);
