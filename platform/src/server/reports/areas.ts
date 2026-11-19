/**
 * Security areas the dashboard reports on, most important first.
 *  - `checks` lists the check keys that cover an area. Add a key only once its scanner ships.
 *  - `tier` ranks how directly a gap in the area leads to a breach:
 *    "essential" means attackers routinely exploit it directly, "important" means it weakens defences,
 *    and "hygiene" means it reduces risk or the blast radius.
 *  - `why` is one plain-English sentence for someone new to security.
 */
export type AreaTier = "essential" | "important" | "hygiene";

export interface SecurityArea { key: string; label: string; tier: AreaTier; why: string; checks: readonly string[] }

export const SECURITY_AREAS: readonly SecurityArea[] = [
  { key: "secrets", label: "Leaked secrets in code", tier: "essential", checks: ["code.secrets"],
    why: "A committed API key or password lets anyone with the code act as you." },
  { key: "exposure", label: "Exposed files (.git, .env, listings)", tier: "essential", checks: ["http.exposure"],
    why: "Public source, config or backup files hand attackers your internals and credentials." },
  { key: "compromise", label: "Signs of compromise (injected scripts, spam)", tier: "essential", checks: ["http.compromise"],
    why: "Injected scripts, miners and hidden spam mean someone already controls part of your site." },
  { key: "blocklist", label: "Blocklisted / malware-flagged", tier: "essential", checks: ["web.blocklist"],
    why: "If Google or abuse lists flag your site, browsers show visitors a red warning and it usually means the site is already hacked." },
  { key: "takeover", label: "Subdomain takeover", tier: "essential", checks: ["dns.takeover"],
    why: "A DNS alias to a deleted service lets anyone claim it and serve content under your name." },
  { key: "deps", label: "Vulnerable dependencies", tier: "essential", checks: ["deps.osv"],
    why: "Known CVEs in libraries are the most common way in, and exploits are often public." },
  { key: "ports", label: "Exposed services / ports", tier: "essential", checks: ["net.exposed_services"],
    why: "Databases, admin panels and remote access open to the internet get attacked within hours." },
  { key: "tls", label: "TLS certificates & configuration", tier: "important", checks: ["tls.cert_expiry", "tls.config"],
    why: "Expired certificates or weak encryption break trust and can expose traffic." },
  { key: "code", label: "Source code analysis (SAST)", tier: "important", checks: ["code.sast"],
    why: "Injection and other unsafe patterns in your own code are fixed most cheaply before release." },
  { key: "containers", label: "Container base images", tier: "important", checks: ["container.image"],
    why: "An outdated base image ships known-vulnerable system packages with every deploy." },
  { key: "iac", label: "Infrastructure as code", tier: "important", checks: ["code.iac"],
    why: "One wrong line in Terraform, Kubernetes or Docker config can open a database to the internet or give a container root on the host." },
  { key: "software", label: "Outdated software and platform", tier: "important", checks: ["web.technology", "webmonitor.packages"],
    why: "An out-of-date CMS, end-of-life PHP or an old JavaScript library carries publicly known flaws attackers scan for." },
  { key: "cors", label: "Cross-origin access (CORS)", tier: "important", checks: ["http.cors"],
    why: "A CORS policy that trusts any website lets other sites read your users' data while they are signed in." },
  { key: "email", label: "Email spoofing (SPF / DMARC)", tier: "important", checks: ["dns.email_posture"],
    why: "Without SPF and DMARC, anyone can send phishing mail that appears to come from your domain." },
  { key: "headers", label: "Web security headers", tier: "hygiene", checks: ["http.security_headers"],
    why: "Browser protections such as HSTS and CSP limit the damage of other flaws." },
  { key: "surface", label: "Attack surface (CT discovery)", tier: "hygiene", checks: ["discovery.ct"],
    why: "Forgotten subdomains are often unpatched. You can only protect what you know about." },
  { key: "caa", label: "Certificate issuance (CAA)", tier: "hygiene", checks: ["dns.caa"],
    why: "CAA limits which authorities can issue certificates for your domain." },
];

export const TIER_LABEL: Record<AreaTier, string> = { essential: "Essential", important: "Important", hygiene: "Good hygiene" };

export function areaByKey(key: string): SecurityArea | undefined {
  return SECURITY_AREAS.find((a) => a.key === key);
}
