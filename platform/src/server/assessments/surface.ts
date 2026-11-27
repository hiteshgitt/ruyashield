import { createHash, randomBytes } from "node:crypto";
import { EgressError, guardedGet, type FetchResult } from "../net/egress";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * pt.surface (automated penetration test, step 1, class A1): ordinary GETs for what an attacker looks at first.
 *  - Sensitive files: phpinfo pages, Apache server-status, .DS_Store, wp-config backups, SQL dumps, backup archives,
 *    PHP debug/error logs, .htpasswd, Subversion metadata.
 *  - Database admin tools reachable from the internet (phpMyAdmin, Adminer).
 *  - WordPress: an unfinished install or setup page anyone could complete, user enumeration (REST API and ?author=),
 *    XML-RPC enabled, and the login page served over plain HTTP.
 * Safety: GET only, no payloads, no parameters beyond ?author=1, no credentials, redirects not followed, at most 4 KB
 * read per response, and evidence never contains file contents (status, type, size and a SHA-256 of the prefix only).
 * A random path is fetched first so a catch-all page is never mistaken for a file. Fails closed: a 5xx, 429 or network
 * error is an error result, never "nothing found".
 */

export const PREFIX_BYTES = 4096;

export type Fetch = (url: string, ctx: CheckContext) => Promise<FetchResult>;
const defaultFetch: Fetch = (url, ctx) =>
  guardedGet(url, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 5000), truncateAt: PREFIX_BYTES, accept: "*/*", followRedirects: false, tlsLenient: true });

const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
type Severity = FindingCandidate["severity"];

interface Probe { path: string; issueKey: string; title: string; severity: Severity; matches: (r: FetchResult) => boolean; remediation: string }

const notHtml = (r: FetchResult) => !/html/i.test(r.contentType ?? "");
const FILES: Probe[] = [
  ...["/phpinfo.php", "/info.php"].map((path) => ({
    path, issueKey: "phpinfo_exposed", title: `PHP configuration page is public (${path})`, severity: "medium" as Severity,
    matches: (r: FetchResult) => /phpinfo\(\)|<h1 class="p">PHP Version/i.test(r.body),
    remediation: "Delete the phpinfo page. It reveals PHP version, modules, paths and environment variables that help an attacker.",
  })),
  { path: "/server-status", issueKey: "server_status_exposed", title: "Apache server-status page is public", severity: "medium",
    matches: (r) => /Apache Server Status for/i.test(r.body),
    remediation: "Restrict mod_status to localhost or your admin IPs (Require local / Require ip ...), or disable it." },
  { path: "/.DS_Store", issueKey: "ds_store_exposed", title: "macOS .DS_Store file lists folder contents", severity: "low",
    matches: (r) => r.body.slice(0, 8).includes("Bud1"),
    remediation: "Delete .DS_Store files from the web root and block dotfiles in the web server configuration." },
  ...["/wp-config.php.bak", "/wp-config.php~", "/wp-config.old", "/wp-config.php.save", "/wp-config.txt"].map((path) => ({
    path, issueKey: "config_backup_exposed", title: `WordPress configuration backup is readable (${path})`, severity: "critical" as Severity,
    matches: (r: FetchResult) => /DB_PASSWORD|DB_USER/.test(r.body),
    remediation: "Delete the backup copy of wp-config.php and change the database password and the authentication keys and salts in it: treat them as leaked.",
  })),
  ...["/backup.sql", "/dump.sql", "/database.sql", "/db.sql"].map((path) => ({
    path, issueKey: "database_dump_exposed", title: `Database dump is downloadable (${path})`, severity: "critical" as Severity,
    matches: (r: FetchResult) => notHtml(r) && /-- (MySQL|MariaDB) dump|CREATE TABLE|INSERT INTO/i.test(r.body),
    remediation: "Remove the dump from the web root now and keep backups outside it. Assume the data, including password hashes, has been copied: rotate credentials and assess whether users must be notified.",
  })),
  ...["/backup.zip", "/site.zip", "/www.zip", "/backup.tar.gz"].map((path) => ({
    path, issueKey: "backup_archive_exposed", title: `Backup archive is downloadable (${path})`, severity: "high" as Severity,
    matches: (r: FetchResult) => notHtml(r) && (r.body.startsWith("PK\u0003\u0004") || (r.body.startsWith("\u001f") && /gzip|tar|octet-stream/i.test(r.contentType ?? ""))),
    remediation: "Remove the archive from the web root and keep backups outside it. It can contain source code, configuration and credentials: rotate any secrets it held.",
  })),
  ...["/wp-content/debug.log", "/debug.log", "/error_log", "/logs/error.log"].map((path) => ({
    path, issueKey: "debug_log_exposed", title: `PHP error log is public (${path})`, severity: "medium" as Severity,
    matches: (r: FetchResult) => notHtml(r) && /PHP (Fatal error|Warning|Notice|Parse error|Deprecated)/.test(r.body),
    remediation: "Delete the log, turn off WP_DEBUG_LOG (or move the log outside the web root) and block .log files. Logs reveal file paths and errors that help an attacker.",
  })),
  { path: "/.htpasswd", issueKey: "htpasswd_exposed", title: "Password file is readable (/.htpasswd)", severity: "high",
    matches: (r) => notHtml(r) && /^[^:\s]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|\$[56]\$)/m.test(r.body),
    remediation: "Block access to .htpasswd (and all dotfiles), move it outside the web root, and change every password in it." },
  { path: "/.svn/entries", issueKey: "svn_exposed", title: "Subversion metadata is public (/.svn/)", severity: "high",
    matches: (r) => notHtml(r) && /^(\d{1,2}|dir)\s*$/m.test(r.body.split(/\r?\n/).slice(0, 3).join("\n")),
    remediation: "Block web access to .svn folders or deploy without them; they can expose source code." },
  ...["/phpmyadmin/", "/pma/"].map((path) => ({
    path, issueKey: "db_admin_exposed", title: `phpMyAdmin is reachable from the internet (${path})`, severity: "medium" as Severity,
    matches: (r: FetchResult) => /phpMyAdmin/i.test(r.body),
    remediation: "Restrict phpMyAdmin to your own IPs or a VPN, or remove it. Exposed database tools are a common target for password guessing and known exploits.",
  })),
  { path: "/adminer.php", issueKey: "db_admin_exposed", title: "Adminer database tool is reachable from the internet (/adminer.php)", severity: "medium",
    matches: (r) => /Adminer/.test(r.body) && /<form/i.test(r.body),
    remediation: "Remove adminer.php or restrict it to your own IPs. Exposed database tools are a common target for password guessing and known exploits." },
];

const WP_REMEDIATION = {
  install: "Finish or remove the installation now: anyone who opens this page can install WordPress with their own admin account and take over the site.",
  usersRest: "Hide the users endpoint from visitors (a security plugin or a rest_endpoints filter that removes /wp/v2/users for logged-out users). Usernames make password guessing easier.",
  usersAuthor: "Stop ?author= redirects from revealing usernames (a security plugin, or a rewrite rule that returns 404 for ?author=N for visitors).",
  xmlrpc: "Disable XML-RPC if nothing uses it (Jetpack and some mobile apps do): a security plugin, or deny /xmlrpc.php in the web server. It allows many password guesses per request.",
  loginHttp: "Redirect all HTTP traffic to HTTPS (and set FORCE_SSL_ADMIN) so passwords are never sent unencrypted.",
};

export function createSurfaceAdapter(fetch: Fetch = defaultFetch, randomPath: () => string = () => `/ruya-${randomBytes(8).toString("hex")}-404check`): CheckAdapter {
  return {
    id: "pt.surface@1", checkKey: "pt.surface", target: "host",
    async run(ctx): Promise<CheckResult> {
      const base = `https://${ctx.host}`;
      const probes: { url: string; status: number; bytes: number }[] = [];
      const get = async (url: string) => {
        const r = await fetch(url, ctx);
        probes.push({ url, status: r.status, bytes: Buffer.byteLength(r.body, "utf8") });
        if (r.status === 429 || r.status >= 500) throw new ProbeFailed(r.status);
        return r;
      };
      const out: FindingCandidate[] = [];
      try {
        const soft = await get(base + randomPath());
        const soft200 = soft.status === 200;
        const softHash = sha256(soft.body);
        const isCatchAll = (r: FetchResult) => soft200 && sha256(r.body) === softHash;
        const evidenceOf = (r: FetchResult) => ({ status: r.status, contentType: r.contentType ? r.contentType.slice(0, 80) : null, bytesRead: Buffer.byteLength(r.body, "utf8"), prefixSha256: sha256(r.body), softNotFound: String(soft.status) });

        for (const p of FILES) {
          const r = await get(base + p.path);
          if (r.status !== 200 || r.redirects > 0 || isCatchAll(r) || !p.matches(r)) continue;
          out.push({ issueKey: p.issueKey, title: p.title, severity: p.severity, location: base + p.path, ...(soft200 ? { confidence: "likely" as const } : {}), evidence: evidenceOf(r), remediation: p.remediation });
        }

        // WordPress checks only when the home page is WordPress.
        const home = await get(base + "/");
        const wordpress = /wp-content|wp-includes/.test(home.body) || /wp-json/i.test(String(home.headers.link ?? ""));
        if (wordpress) {
          for (const path of ["/wp-admin/install.php", "/wp-admin/setup-config.php"]) {
            const r = await get(base + path);
            if (r.status === 200 && !isCatchAll(r) && /name="weblog_title"|setup-config\.php\?step=1/.test(r.body)) {
              out.push({ issueKey: "wp_install_open", title: `WordPress installation can be completed by anyone (${path})`, severity: "critical", location: base + path, evidence: evidenceOf(r), remediation: WP_REMEDIATION.install });
            }
          }
          const users = await get(base + "/wp-json/wp/v2/users");
          if (users.status === 200 && /^\s*\[/.test(users.body) && /"slug"\s*:/.test(users.body)) {
            out.push({ issueKey: "wp_user_enum_rest", title: "WordPress lists usernames to anyone (/wp-json/wp/v2/users)", severity: "medium", location: base + "/wp-json/wp/v2/users", evidence: { ...evidenceOf(users), usersShown: (users.body.match(/"slug"\s*:/g) ?? []).length }, remediation: WP_REMEDIATION.usersRest });
          }
          const author = await get(base + "/?author=1");
          const loc = String(author.headers.location ?? "");
          if (author.status >= 300 && author.status < 400 && /\/author\/[^/?#]+/.test(loc)) {
            out.push({ issueKey: "wp_user_enum_author", title: "WordPress reveals usernames through ?author= redirects", severity: "low", location: base + "/?author=1", evidence: { status: author.status, redirectsToAuthorPage: true }, remediation: WP_REMEDIATION.usersAuthor });
          }
          const xmlrpc = await get(base + "/xmlrpc.php");
          if (/XML-RPC server accepts POST requests only/i.test(xmlrpc.body)) {
            out.push({ issueKey: "wp_xmlrpc_enabled", title: "WordPress XML-RPC is enabled (/xmlrpc.php)", severity: "low", location: base + "/xmlrpc.php", evidence: { status: xmlrpc.status }, remediation: WP_REMEDIATION.xmlrpc });
          }
          const login = await get(`http://${ctx.host}/wp-login.php`);
          if (login.status === 200 && login.redirects === 0 && /name="pwd"|id="user_pass"/.test(login.body)) {
            out.push({ issueKey: "login_over_http", title: "WordPress login page works over plain HTTP", severity: "medium", location: `http://${ctx.host}/wp-login.php`, evidence: { status: login.status }, remediation: WP_REMEDIATION.loginHttp });
          }
        }
        return { status: "ok", findings: out, evidence: { wordpress, probes } };
      } catch (e) {
        if (e instanceof ProbeFailed) return { status: "error", reason: `http_${e.status}`, evidence: { probes } };
        if (e instanceof EgressError) return { status: "error", reason: e.code === "network" ? "host_unreachable" : e.code, evidence: { error: e.message.slice(0, 200), probes } };
        throw e;
      }
    },
  };
}

class ProbeFailed extends Error { constructor(public status: number) { super(`http_${status}`); } }
