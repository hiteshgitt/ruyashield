/**
 * Classifies one web request as suspicious (and which kind) or benign. Used for log-agent lines.
 * Signature matching only: this never replays or tests anything. Benign requests return null and are never stored.
 * The query string is examined for signatures but never stored (it can carry personal data or tokens).
 */
export const ATTACK_TYPES = {
  sqli: "SQL injection attempt",
  xss: "Cross-site scripting attempt",
  traversal: "Path traversal / file read attempt",
  rce: "Command / code injection attempt",
  sensitive_probe: "Probe for secrets or config files",
  admin_bruteforce: "Login brute force / admin probing",
  scanner: "Vulnerability scanner",
  shell_probe: "Web-shell / backdoor probe",
  waf_block: "Blocked by firewall",
  challenge: "Challenged by firewall",
  rate_limit: "Rate limited",
  bot: "Bad bot",
  other: "Other firewall event",
} as const;
export type AttackType = keyof typeof ATTACK_TYPES;

const RULES: ReadonlyArray<[AttackType, RegExp]> = [
  ["sqli", /(\bunion\b[\s+/*]+(all[\s+/*]+)?select\b|\bselect\b.+\bfrom\b.+\bwhere\b|\b(or|and)\b[\s+]+['"]?\d+['"]?\s*=\s*['"]?\d|sleep\s*\(\s*\d|benchmark\s*\(|information_schema|waitfor[\s+]+delay|'\s*(or|and)\s*'|;\s*drop\s+table)/i],
  ["xss", /(<\s*script|%3cscript|javascript:|onerror\s*=|onload\s*=|<\s*svg[^>]*on\w+=|alert\s*\(|document\.cookie)/i],
  ["traversal", /(\.\.\/|\.\.%2f|%2e%2e%2f|%2e%2e\/|\.\.\\|\/etc\/passwd|\/proc\/self|c:\\windows|boot\.ini|win\.ini)/i],
  ["rce", /(\$\{jndi:|\bcmd=|;\s*(cat|wget|curl|bash|sh)\s|\|\s*(cat|id|whoami)\b|`[^`]*`|\$\((id|whoami|cat)|phpinfo\(|base64_decode\(|\beval\(|\/bin\/(ba)?sh)/i],
  ["sensitive_probe", /(\/\.env(\.\w+)?$|\/\.git\/|\/\.svn\/|\/\.aws\/|\/\.ssh\/|\/\.htpasswd|\/wp-config\.php(\.\w+)?$|\/config\.(php|json|yml|yaml)\.(bak|old|save)|\/backup\.(zip|sql|tar\.gz)|\/(db|dump|database)\.sql|\/\.DS_Store|\/server-status|\/phpinfo\.php|\/actuator\/(env|heapdump))/i],
  ["shell_probe", /\/(shell|c99|r57|wso|alfa|b374k|indoxploit|webshell|cmd|up|uploader|leaf|mini)\.(php|asp|aspx|jsp)$/i],
  ["admin_bruteforce", /(\/wp-login\.php|\/xmlrpc\.php|\/administrator\/index\.php|\/user\/login|\/phpmyadmin|\/pma\/|\/adminer\.php|\/manager\/html|\/admin\/login)/i],
];

const SCANNER_UA = /(sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|acunetix|nessus|openvas|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|hydra|joomscan|whatweb|netsparker|qualys|burp|zmeu|python-requests\/|go-http-client\/1\.1$|libwww-perl|curl\/\d)/i;

export interface Req { method: string | null; target: string; status: number | null; userAgent: string | null }

export function classify(r: Req): AttackType | null {
  let decoded = r.target;
  try { decoded = decodeURIComponent(r.target.replace(/\+/g, " ")); } catch { /* keep raw */ }
  const path = splitPath(r.target);
  for (const [type, re] of RULES) {
    // Path-shaped rules check the path only; payload rules check the whole target (raw and decoded).
    const onPath = type === "sensitive_probe" || type === "shell_probe" || type === "admin_bruteforce";
    if (onPath ? re.test(path) : re.test(r.target) || re.test(decoded)) {
      // A successful GET of the login page is normal; POSTs and 4xx on these paths are not.
      if (type === "admin_bruteforce" && r.method === "GET" && r.status !== null && r.status < 400) continue;
      // A probe for .env/.git that the server answered 404/403 is still a probe worth showing.
      return type;
    }
  }
  if (r.userAgent && SCANNER_UA.test(r.userAgent) && !/curl\/\d/i.test(r.userAgent)) return "scanner";
  if (r.userAgent && /curl\/\d/i.test(r.userAgent) && r.status !== null && r.status >= 400) return "scanner";
  return null;
}

/** Path only: no query string, no fragment, capped. */
export function splitPath(target: string): string {
  const p = target.split(/[?#]/, 1)[0] || "/";
  return p.slice(0, 300);
}
