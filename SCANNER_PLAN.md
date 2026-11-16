# Scanner plan: from 4 posture checks to real vulnerability coverage

Status: proposal · 2026-11-09 · scope: `platform/`

## Where we are

RuyaShield runs four checks today (`platform/src/server/assessments/checks.ts`, `ENGINE_VERSION ruya-checks/0.2.0`):

| checkKey | Class | What it sees |
|---|---|---|
| `tls.cert_expiry` | A1 | certificate validity / expiry |
| `http.security_headers` | A1 | HSTS, CSP, X-Frame-Options, etc. |
| `dns.email_posture` | P | SPF / DMARC |
| `dns.caa` | P | CAA records |

These are hygiene checks, not vulnerability scanning. RuyaShield does **not** currently look at code, dependencies, secrets or open ports. The dashboard's "What we check" card says so ("Not scanned yet"), and that must stay true until each scanner below ships.

## Rules every new scanner follows

These rules already apply to the existing checks and carry over unchanged:

1. **Fail closed.** If a scanner could not observe something, it returns `{ status: "error" }`, never "no findings". `normalizeResult` already enforces this for adapters. Repo scanners get the same zod-validated result shape.
2. **Scope guard on every hop.** Host scanners only reach the network through `ctx.onHop` / `guardedGet` / `tlsProbe`. They run only against **verified** assets.
3. **No exploitation.** No payloads, fuzzing, credential use, brute force or auth bypass. Class X stays adapter-less.
4. **Evidence without the secret.** Store proof, not sensitive values: hashes, redacted prefixes, line numbers, response codes.
5. **Stable fingerprints.** `fingerprint(checkKey, location, issueKey)` drives finding dedup, re-tests and `resolved_verified`. Choose `location` and `issueKey` so a fix makes the finding disappear on re-test.
6. **Dashboard coverage is code, not copy.** When a scanner ships, add its checkKey to `SECURITY_AREAS` in `src/server/reports/insights.ts`, and update the test in `tests/unit/insights.test.ts`, which asserts the exact covered list.

## Two kinds of scanner

| | Host scanners (5–7, ports) | Repository scanners (1, 2, 4) |
|---|---|---|
| Target | `assets` (verified host) | `repository_integrations` (`local_git` today) |
| Runs in | existing assessment worker → `ADAPTERS` | new repo-scan job → `remediation/sandbox.ts` |
| Network | through scope guard | **none** except the advisory DB (OSV) |
| Finding attaches to | `assetId` | needs a target (see below) |

**Data-model change needed for repo scanners.** `findings.assetId` is NOT NULL and assets are hosts. The recommended fix is an asset `kind: "host" | "repository"`, with repository assets linked 1:1 to a `repository_integrations` row. This keeps findings, lifecycle, re-tests, SLAs, reports and the dashboard block map working unchanged. Repo assets skip DNS/HTTP ownership verification, because org admins connect the repo themselves. The alternative is a nullable `findings.repositoryId`, which touches every finding query; avoid it.

---

## 1. Dependency CVEs (OSV) · `deps.osv` · highest value

- **Approach.** Parse lockfiles in the repo: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements*.txt`, `poetry.lock`, `go.sum`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`. Query the OSV.dev batch API (`POST /v1/querybatch`) with `{ecosystem, name, version}`.
  - Option: run Google's `osv-scanner` binary in the sandbox instead of writing parsers. It is faster to ship, but adds a pinned binary dependency. **Recommendation: use osv-scanner (pinned version, checksum-verified) and parse its JSON.**
- **Finding shape.**
  - `issueKey` = vulnerability ID (`GHSA-…`/`CVE-…`); `location` = `lockfile#package@version`.
  - Severity comes from the CVSS vector in OSV, falling back to `database_specific.severity`.
  - Remediation is the "fixed in" version.
  - When OSV gives no severity, use `confidence: "likely"`.
- **Evidence.** Advisory IDs, affected range, fixed version, lockfile path, and the lockfile's SHA-256.
- **Re-test.** Re-scan after a commit. If the package version moves past the fixed range, the finding resolves.
- **Safety.** The only egress is to `api.osv.dev`, on an allowlist. No code leaves the box; only package names and versions are sent.
- **Effort.** About 3–4 days, plus the repo-asset model change (about 2 days, shared with 2 and 4).

## 2. Secrets · `code.secrets`

- **Approach.** Run `gitleaks` (pinned) in the sandbox over the working tree, and optionally over the last N commits of history. Use its default ruleset plus entropy checks.
- **Finding shape.**
  - `issueKey` = rule ID (e.g. `aws-access-key`); `location` = `path:line`, or `commit:path:line` for history.
  - Severity:
    - Live-format cloud or payment keys: critical.
    - Private keys and tokens: high.
    - Generic high-entropy strings: medium, with `confidence: "suspected"`.
- **Evidence.** **Never store the secret.** Store the rule, file, line, the first 4 characters plus length, and the SHA-256 of the value, so the finding can be deduplicated without keeping the secret.
- **Remediation text.** *Rotate first, then remove.* Deleting the line does not un-leak the secret. A finding found in history is only resolved by rotation, so mark it `resolved_unverified` and require an attestation.
- **Safety.** Offline only. **Never test whether a found key works.** That is credential use (class X).
- **Effort.** About 2–3 days.

## 3. Exposed ports · `net.exposed_services`

- **Approach.** Use plain TCP connect, not raw SYN, against a fixed list of about 30 risky ports:

  | Category | Ports |
  |---|---|
  | Remote access | 21, 22, 23, 3389, 5900 |
  | Databases | 1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017 |
  | Admin / container | 2375, 2376, 5000, 8080, 8443, 9090, 10250 |
  | Mail | 25, 110, 143 |
  | Other | 445, 161 (UDP, skipped), … |

  Only record that the port is open. Read at most 256 bytes of banner, and never send protocol commands.
- **Class.** A2: more intrusive than A1, so it needs a per-org opt-in in the plan or safety settings, plus a per-host rate limit (≤ 5 connections/s, ≤ 1 scan per host per hour) and a kill switch (`kill_switches` already exists).
- **Finding shape.**
  - `issueKey` = `port-<n>`; `location` = `host:port`.
  - Severity: databases and Docker/Kubelet are critical, RDP/VNC/Telnet are high, SSH is info.
- **Safety.** Resolve once and connect only to the resolved IPs that passed the scope guard, to block DNS-rebinding into internal ranges. The private-range block in `net/egress` must apply to raw sockets too, which needs a new `tcpProbe` beside `tlsProbe`.
- **Effort.** About 3 days, including the egress primitive and its tests.

## 4. SAST · `code.sast`

- **Approach.** Run `semgrep` (pinned) with the community `p/default` plus `p/secrets`-free rulesets, offline (`--metrics=off`, local rules vendored at a fixed commit).
- **Finding shape.**
  - `issueKey` = rule ID; `location` = `path:line`.
  - Severity comes from rule metadata.
  - Set `confidence: "suspected"` unless the rule says HIGH confidence, because SAST has a high false-positive rate.
- **Triage UX.** Default the dashboard filter to medium+ for SAST. Existing risk acceptance covers false positives.
- **Safety.** Offline only. Never send code to an AI or a third party unless an org explicitly enables the existing AI analysis.
- **Effort.** About 3–4 days. Most of the work is tuning noise.

## 5. Certificate transparency / subdomains · `discovery.ct`

- **Approach.** Query crt.sh JSON (or Cert Spotter as a fallback) for `%.domain`. This is class P (passive): it never touches the target.
- **Output is not findings.** It produces **suggested assets** ("we found 14 subdomains of example.com"). They must pass ownership verification before any active check runs.
- **Findings it can raise.**
  - `issueKey` = `wildcard-cert` (info).
  - `issueKey` = `unknown-issuer`, when the issuing CA is not allowed by CAA (low).
- **Safety.** Third-party API only, rate-limited and cached for 24 hours.
- **Effort.** About 2 days, plus the "suggested assets" UI (about 1–2 days).

## 6. TLS configuration quality · `tls.config`

- **Approach.** Extend `tlsProbe` to attempt handshakes pinned to TLS 1.0, 1.1, 1.2 and 1.3. Record the negotiated cipher, the key size and whether the chain is complete.
- **Findings and severity.**

  | Issue | Severity |
  |---|---|
  | TLS 1.0 / 1.1 enabled | medium |
  | Weak cipher (RC4, 3DES, CBC-SHA1 export) | medium |
  | RSA key < 2048 | high |
  | Incomplete chain | low |
  | No TLS 1.3 | info |

- **Class.** A1: a few handshakes only.
- **Effort.** About 2 days. Note that Node's OpenSSL may refuse old protocols, so check `minVersion` support in CI.

## 7. Basic web checks · `http.exposure`

- **Approach.** A handful of GETs through `guardedGet`:

  | Probe | Request | Counts as found when |
  |---|---|---|
  | Exposed `.git` | `/.git/HEAD` | 200 and body starts `ref:` → **critical** |
  | Exposed `.env` | `/.env` | 200, `text/plain`-ish, matches `^[A-Z_]+=` on the first line → **critical** |
  | Directory listing | `/`, plus common asset dirs | body contains `Index of /` → low |
  | Cookie flags | main page | `Set-Cookie` without `Secure` / `HttpOnly` / `SameSite` → low; session-looking names → medium |

  Never download beyond 512 bytes. **Never store `.env` contents**: store only the status code, content type, byte count and the SHA-256 of the prefix.
- **Soft-404 guard.** First fetch a random path. If it returns 200 with the same body hash, mark the result `confidence: "unknown"` and do not raise a critical.
- **Class.** A1.
- **Effort.** About 2 days.

---

## Suggested order and milestones

| Milestone | Ships | Unlocks on dashboard | Est. |
|---|---|---|---|
| M1 | Repo-asset model + sandbox job runner + **deps.osv** | "Dependency vulnerabilities" | ~1.5 wk |
| M2 | **code.secrets** | "Leaked secrets in code" | ~0.5 wk |
| M3 | `tcpProbe` + **net.exposed_services** (opt-in) | "Exposed services / ports" | ~0.5 wk |
| M4 | **code.sast** | "Source code analysis" | ~1 wk |
| M5 | **discovery.ct** + suggested assets | new "Attack surface" area | ~0.5 wk |
| M6 | **tls.config**, **http.exposure** | extend TLS area, new "Exposed files" area | ~1 wk |

For each milestone, the definition of done:

- The adapter has unit tests with recorded fixtures.
- It returns `error` on any parse or network failure, and a test proves this.
- `ENGINE_VERSION` is bumped.
- The `check_definitions` row is seeded.
- The `SECURITY_AREAS` entry and test are updated.
- The finding remediation text is written.
- A re-test turns the finding into `resolved_verified` on a fixture where it is fixed.

## Out of scope (on purpose)

- Authenticated/DAST crawling, injection testing, brute force and default-credential tests: class X.
- Testing whether leaked keys are live.
- Container image scanning. This could later reuse OSV via `syft` SBOMs after M1.
