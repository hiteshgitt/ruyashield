import { Suspense } from "react";
import { AccountCta } from "./_components/SiteHeader";
import { Reveal } from "./_components/Reveal";
import { Workflow } from "./_components/Workflow";
import { SiteMotion } from "./_components/SiteMotion";

/*
 * Public home page. Every product statement here matches what the platform does today; every mock UI is
 * labelled as an illustrative example on example.com and never presented as live data.
 */

function Cta({ size = "lg" }: { size?: "sm" | "lg" }) {
  return (
    <Suspense fallback={<a className={`btn btn-primary btn-${size}`} href="/auth/login">Sign in to get started</a>}>
      <AccountCta size={size} />
    </Suspense>
  );
}

export default function Home() {
  return (
    <>
      <Hero />
      <Problem />
      <section id="workflow" className="section wrap" aria-labelledby="workflow-title">
        <Reveal className="section-head split">
          <div>
            <span className="eyebrow">How it works</span>
            <h2 id="workflow-title" className="display" style={{ marginTop: "1.25rem" }}>Six stages, from first signal to <em>proven</em> fix.</h2>
          </div>
          <p className="lead">Detect, investigate, validate, prepare the fix, verify it and keep watching. Each stage leaves a record, and nothing moves forward on an assumption.</p>
        </Reveal>
        <Workflow />
      </section>
      <Zealot />
      <Prioritize />
      <FixProof />
      <Agencies />
      <WebMonitor />
      <Capabilities />
      <Reports />
      <Pricing />
      <Faq />
      <section className="section wrap final" aria-labelledby="final-title">
        <Reveal>
          <h2 id="final-title" className="display">Stop guessing whether it&rsquo;s <em>fixed.</em></h2>
          <p className="lead">Verify the assets you own, let Zealot explain what it found, and close findings only when a re-test proves it.</p>
          <div className="hero-cta"><Cta /><a className="btn btn-ghost btn-lg" href="#workflow">See the workflow</a></div>
        </Reveal>
      </section>
      <SiteMotion />
    </>
  );
}

function Hero() {
  return (
    <section className="hero wrap" aria-labelledby="hero-title">
      <div className="hero-grid">
        <div className="hero-copy">
          <span className="eyebrow">Website security for agencies, MSPs and teams</span>
          <h1 id="hero-title" className="hero-title">Find the real risk. <em>Prove</em> the&nbsp;fix.</h1>
          <p className="lead">RuyaShield checks the websites you&rsquo;re authorized to test, has Zealot explain each finding with cited evidence, and only calls something fixed after a re-test passes.</p>
          <div className="hero-cta"><Cta /><a className="btn btn-ghost btn-lg" href="#workflow">How it works</a></div>
          <ul className="hero-facts">
            <li>Tests only assets with verified ownership</li>
            <li>AI suggestions are labelled — they never change a finding</li>
            <li>Inconclusive is never reported as passed</li>
          </ul>
        </div>
        <div className="console-stage">
          <HeroConsole />
        </div>
      </div>
    </section>
  );
}

function HeroConsole() {
  return (
    <figure className="frame console" aria-label="Illustrative example of a RuyaShield finding view; not live data">
      <div className="frame-bar">
        <span className="frame-title"><span className="frame-dots" aria-hidden="true"><i /><i /><i /></span>Findings · shop.example.com</span>
        <span className="illus">Illustrative example — not live data</span>
      </div>
      <div className="frame-body">
        <div className="console-asset">
          <div><strong>shop.example.com</strong><small>Client group · Example Retail</small></div>
          <span className="pill pill-ok">Ownership verified · DNS</span>
        </div>
        <div className="console-cols">
          <div>
            <h3>Latest checks</h3>
            <ul className="checks">
              <li><b>Security headers</b><code>http.security_headers</code><span className="pill pill-bad">High · confirmed</span></li>
              <li><b>Certificate expiry</b><code>tls.cert_expiry</code><span className="pill pill-warn">Medium · new</span></li>
              <li><b>Email posture</b><code>dns.email_posture</code><span className="pill pill-ok">No finding</span></li>
              <li><b>CAA record</b><code>dns.caa</code><span className="pill pill-info">Info · triaged</span></li>
            </ul>
          </div>
          <div className="zealot-card">
            <header><span className="zealot-glyph" aria-hidden="true">Z</span>Zealot · AI explanation</header>
            <p>The response for <code>/checkout</code> has no Content-Security-Policy header [E1]. Third-party scripts load on that page [E2], so a policy is likely worth adding first.</p>
            <div className="tags"><span className="pill pill-info">Observation</span><span className="pill pill-violet">Inference · likely</span></div>
            <footer>AI suggestion — not a verified result.</footer>
          </div>
        </div>
        <div className="console-foot">
          <span>Fix verification</span>
          <span className="pill pill-warn">Awaiting re-test</span>
        </div>
      </div>
    </figure>
  );
}

function Problem() {
  return (
    <section className="section wrap" aria-labelledby="problem-title">
      <div className="problem-grid">
        <Reveal>
          <span className="eyebrow">The problem</span>
          <h2 id="problem-title" className="display" style={{ marginTop: "1.25rem" }}>More alerts don&rsquo;t make a site <em>safer.</em></h2>
        </Reveal>
        <Reveal>
          <ol className="problem-list">
            <li><div><h3>Scanners hand you volume, not decisions.</h3><p>The same issue shows up run after run, with no record of who looked at it, what they decided or why.</p></div></li>
            <li><div><h3>AI answers sound certain when they aren&rsquo;t.</h3><p>A confident paragraph with no evidence behind it is worse than no answer — especially when it says something is &ldquo;fixed&rdquo;.</p></div></li>
            <li><div><h3>&ldquo;Fixed&rdquo; usually means someone said so.</h3><p>Without a re-test, a closed ticket is a guess. Without regression checks, the same problem quietly comes back.</p></div></li>
          </ol>
        </Reveal>
      </div>
    </section>
  );
}

function Zealot() {
  return (
    <section id="zealot" className="section wrap zealot" aria-labelledby="zealot-title">
      <Reveal className="section-head split">
        <div>
          <span className="eyebrow">Zealot · AI investigation</span>
          <h2 id="zealot-title" className="display" style={{ marginTop: "1.25rem" }}>An assistant that <em>shows its work.</em></h2>
        </div>
        <p className="lead">Zealot explains findings in plain language, but every claim must point at stored evidence. It suggests; your team decides.</p>
      </Reveal>
      <div className="zealot-grid">
        <Reveal>
          <figure className="frame" aria-label="Illustrative example of a Zealot explanation; not live data">
            <div className="frame-bar">
              <span className="frame-title"><span className="zealot-glyph" aria-hidden="true">Z</span>Explanation · missing CSP</span>
              <span className="illus">Illustrative example — not live data</span>
            </div>
            <div className="frame-body">
              <ul className="evidence" aria-label="Evidence">
                <li><b>E1</b><span>Response headers for https://shop.example.com/checkout</span></li>
                <li><b>E2</b><span>Script sources found in the stored page response</span></li>
              </ul>
              <div className="claims">
                <div className="claim">
                  <div className="claim-head"><span className="pill pill-info">Observation</span><span className="pill pill-ok">Confirmed</span></div>
                  <p>No Content-Security-Policy header is sent on the checkout page.</p>
                  <span className="cite">Cites E1</span>
                </div>
                <div className="claim">
                  <div className="claim-head"><span className="pill pill-violet">Inference</span><span className="pill pill-warn">Likely</span></div>
                  <p>Injected script would run without restriction on this page.</p>
                  <span className="cite">Cites E1, E2</span>
                </div>
                <div className="claim">
                  <div className="claim-head"><span className="pill pill-warn">Recommendation</span><span className="pill pill-mute">Possible</span></div>
                  <p>Deploy a report-only policy first, then enforce once reports are clean.</p>
                  <span className="cite">Cites E1, E2</span>
                </div>
                <div className="claim dropped">
                  <div className="claim-head"><span className="pill pill-bad">Dropped · no evidence</span></div>
                  <p>The site has already been compromised.</p>
                  <span className="cite">Unsupported claims are removed and counted, not shown as findings.</span>
                </div>
              </div>
            </div>
          </figure>
        </Reveal>
        <Reveal>
          <ul className="guard-list">
            <li><b>Cited, or it doesn&rsquo;t ship</b><span>Claims must reference evidence labels like E1 and E2. Anything unsupported is dropped, and the count is shown.</span></li>
            <li><b>Typed and graded</b><span>Each claim is an observation, an inference or a recommendation, with confidence: confirmed, likely or possible.</span></li>
            <li><b>No claims of compromise or &ldquo;fixed&rdquo;</b><span>Zealot isn&rsquo;t allowed to say a site was breached or a fix worked. Only a re-test can establish that.</span></li>
            <li><b>Website content is data, not instructions</b><span>Text pulled from a scanned site is treated as untrusted input, so a page can&rsquo;t steer the assistant. Secrets are redacted before analysis.</span></li>
            <li><b>Advisory only, and optional</b><span>Nothing Zealot says changes a finding. Organizations can turn it off entirely.</span></li>
          </ul>
          <div className="legend" aria-label="Claim labels">
            <span className="pill pill-info">Observation</span><span className="pill pill-violet">Inference</span><span className="pill pill-warn">Recommendation</span><span className="pill pill-mute">Inconclusive · evidence missing</span>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

function Prioritize() {
  return (
    <section className="section wrap" aria-labelledby="prio-title">
      <div className="prio-grid">
        <Reveal>
          <span className="eyebrow">Risk prioritization</span>
          <h2 id="prio-title" className="display" style={{ marginTop: "1.25rem" }}>One finding per problem, <em>ranked by people.</em></h2>
          <p className="lead" style={{ marginTop: "1.5rem" }}>Repeat sightings collapse into a single finding with an occurrence history. Severity is a decision someone makes and explains — not a number nobody owns.</p>
          <div className="facts">
            <div><h3>Reasons on record</h3><p>Every severity change stores who set it and why.</p></div>
            <div><h3>Owners and due dates</h3><p>Confirmed findings get an owner and a deadline.</p></div>
            <div><h3>Honest dismissals</h3><p>A false positive needs an evidence class. Accepted risk expires.</p></div>
            <div><h3>No silent closes</h3><p>Findings that stop appearing go stale, not resolved.</p></div>
          </div>
        </Reveal>
        <Reveal>
          <figure className="frame" aria-label="Illustrative example of a findings queue; not live data">
            <div className="frame-bar">
              <span className="frame-title"><span className="frame-dots" aria-hidden="true"><i /><i /><i /></span>Findings queue</span>
              <span className="illus">Illustrative example — not live data</span>
            </div>
            <div className="prio-table-wrap" tabIndex={0} role="region" aria-label="Findings queue example (scrolls sideways)">
              <table className="prio-table">
                <thead><tr><th scope="col">Finding</th><th scope="col">Severity</th><th scope="col">Status</th><th scope="col">Seen</th></tr></thead>
                <tbody>
                  <tr><td>CSP header missing<small>shop.example.com</small></td><td><span className="pill pill-bad">High</span></td><td><span className="pill pill-violet">In remediation</span></td><td>6 occurrences</td></tr>
                  <tr><td>Certificate expires soon<small>api.example.com</small></td><td><span className="pill pill-warn">Medium</span></td><td><span className="pill pill-violet">Confirmed</span></td><td>2 occurrences</td></tr>
                  <tr><td>DMARC policy is p=none<small>example.com</small></td><td><span className="pill pill-warn">Low</span></td><td><span className="pill pill-mute">Accepted risk · expires</span></td><td>4 occurrences</td></tr>
                  <tr><td>No CAA record<small>blog.example.com</small></td><td><span className="pill pill-info">Info</span></td><td><span className="pill pill-mute">False positive · evidenced</span></td><td>1 occurrence</td></tr>
                </tbody>
              </table>
            </div>
          </figure>
        </Reveal>
      </div>
    </section>
  );
}

function FixProof() {
  const steps = [
    ["Plan", "A remediation plan is written against the finding."],
    ["Approve", "Someone other than the requester approves, with MFA step-up. Approvals expire after 7 days."],
    ["Branch", "Changes go to a ruyashield/<plan>-v<n> branch in your connected repository."],
    ["Sandbox", "Diff safety checks, then a run with no network and a 120-second limit."],
    ["Re-test", "The original check runs again against the live asset."],
    ["FixProof", "A verified result creates a FixProof record with the evidence."],
  ];
  const outcomes: [string, string, string][] = [
    ["pill-ok", "Verified", "The re-test passed. A FixProof record is created."],
    ["pill-warn", "Partially verified", "Some checks passed and some didn’t. The finding stays open."],
    ["pill-bad", "Failed", "The issue is still there. Owners are notified; this can’t be muted."],
    ["pill-mute", "Inconclusive", "The re-test couldn’t decide. Never counted as a pass."],
    ["pill-mute", "Not run", "The re-test couldn’t start. Reported, never assumed."],
  ];
  return (
    <section id="fixproof" className="section wrap fixproof" aria-labelledby="fixproof-title">
      <Reveal className="section-head split">
        <div>
          <span className="eyebrow">Remediation · FixProof</span>
          <h2 id="fixproof-title" className="display" style={{ marginTop: "1.25rem" }}>A fix counts when it&rsquo;s <em>re-tested.</em></h2>
        </div>
        <p className="lead">Prepare the change with approvals and a sandbox, then prove it with the same check that found the problem. Nothing is merged or deployed for you.</p>
      </Reveal>
      <Reveal>
        <ol className="timeline">
          {steps.map(([t, d]) => <li key={t}><h3>{t}</h3><p>{d}</p></li>)}
        </ol>
      </Reveal>
      <Reveal className="outcomes">
        {outcomes.map(([cls, label, d]) => (
          <div key={label}><span className={`pill ${cls}`}>{label}</span><p>{d}</p></div>
        ))}
      </Reveal>
      <p className="outcomes-note">The five verification outcomes. Only &ldquo;Verified&rdquo; resolves a finding.</p>
    </section>
  );
}

function Agencies() {
  return (
    <section id="agencies" className="section wrap" aria-labelledby="agencies-title">
      <div className="agency-grid">
        <Reveal>
          <span className="eyebrow">Agencies &amp; MSPs</span>
          <h2 id="agencies-title" className="display" style={{ marginTop: "1.25rem" }}>Many clients. <em>Clear lines</em> between them.</h2>
          <p className="lead" style={{ marginTop: "1.5rem" }}>Group assets by client, scope people to the clients they work on, and keep a separate, tamper-evident record of every action.</p>
          <div className="feature-list">
            <div><h3>Client groups</h3><p>Members can be limited to specific client groups, so a contractor sees only their client.</p></div>
            <div><h3>Scoped API tokens</h3><p>Read-mostly tokens, shown once and stored hashed. A token can&rsquo;t approve, delete or administer.</p></div>
            <div><h3>Kill switch and audit log</h3><p>Stop all testing for an organization in one action. Every change is recorded in a hash-chained log.</p></div>
          </div>
        </Reveal>
        <Reveal>
          <figure className="frame" aria-label="Illustrative example of client groups; not live data">
            <div className="frame-bar">
              <span className="frame-title"><span className="frame-dots" aria-hidden="true"><i /><i /><i /></span>Client groups</span>
              <span className="illus">Illustrative example — not live data</span>
            </div>
            <div className="frame-body">
              <div className="clients">
                <div className="client"><b>Example Retail</b><small>3 assets · 2 members</small><span className="pill pill-bad">1 high open</span></div>
                <div className="client"><b>Example Clinic</b><small>2 assets · 1 member</small><span className="pill pill-warn">Fix awaiting re-test</span></div>
                <div className="client"><b>Example Studio</b><small>4 assets · 3 members</small><span className="pill pill-ok">No open findings</span></div>
              </div>
              <div className="roles" aria-label="Roles">
                {["org_admin", "security_lead", "analyst", "developer", "approver", "viewer", "service"].map((r) => <span key={r} className="role">{r}</span>)}
              </div>
            </div>
          </figure>
        </Reveal>
      </div>
    </section>
  );
}

function WebMonitor() {
  return (
    <section className="section wrap" aria-labelledby="webmonitor-title">
      <Reveal className="handoff">
        <div>
          <span className="eyebrow">WebMonitor handoff</span>
          <h2 id="webmonitor-title" className="display" style={{ marginTop: "1.25rem", fontSize: "var(--fs-title)" }}>Uptime problems go to WebMonitor &mdash; only with consent.</h2>
          <p className="lead" style={{ marginTop: "1rem", fontSize: "1.0625rem" }}>When a finding is about availability rather than security, RuyaShield can offer a referral to WebMonitor. It never launches anything on its own, and only a status and a link come back.</p>
        </div>
        <ol className="handoff-steps">
          <li><span className="mono">01</span><b>Offer</b><p>The finding suggests a referral.</p></li>
          <li><span className="mono">02</span><b>Consent</b><p>A person agrees before anything is shared.</p></li>
          <li><span className="mono">03</span><b>Status</b><p>Only the referral status and a link return.</p></li>
        </ol>
      </Reveal>
    </section>
  );
}

function Capabilities() {
  const caps = [
    ["scope", "Ownership verification", "DNS TXT or hosted-file proof before any test runs against an asset."],
    ["checks", "Non-intrusive checks", "TLS certificate expiry, HTTP security headers, SPF/DMARC email posture and CAA records."],
    ["triage", "Finding lifecycle", "Ten statuses from new to resolved-verified, including reopened and stale, with every transition recorded."],
    ["ai", "Zealot explanations", "Evidence-cited claims with type and confidence. Optional per organization."],
    ["fix", "Approved remediation", "Plans, separate approvers, MFA step-up, branches and a network-less sandbox."],
    ["verify", "FixProof & regressions", "Re-tests on demand and on your interval; regressions reopen the finding."],
    ["notify", "Notifications", "Thirteen kinds, in-app and email. Security-critical ones can't be turned off."],
    ["govern", "Governance", "Seven roles, client-group scoping, a kill switch and a tamper-evident audit log."],
    ["report", "Reports & API", "CSV and PDF reports with a SHA-256 checksum, and a read-mostly REST API."],
  ];
  return (
    <section className="section wrap" aria-labelledby="caps-title">
      <Reveal className="section-head split">
        <div>
          <span className="eyebrow">Capabilities</span>
          <h2 id="caps-title" className="display" style={{ marginTop: "1.25rem" }}>What&rsquo;s in the platform <em>today.</em></h2>
        </div>
        <p className="lead">A focused set, built to be trusted rather than to cover everything. No intrusive testing runs automatically.</p>
      </Reveal>
      <Reveal>
        <ul className="caps">
          {caps.map(([k, t, d]) => <li key={k}><span className="mono">{k}</span><h3>{t}</h3><p>{d}</p></li>)}
        </ul>
      </Reveal>
    </section>
  );
}

function Reports() {
  return (
    <section className="section wrap" aria-labelledby="reports-title">
      <div className="report-grid">
        <Reveal>
          <span className="eyebrow">Reports &amp; evidence</span>
          <h2 id="reports-title" className="display" style={{ marginTop: "1.25rem" }}>Evidence your clients can <em>check.</em></h2>
          <p className="lead" style={{ marginTop: "1.5rem" }}>Export findings as CSV or PDF. Each file is stored as generated and served with its SHA-256 checksum, so a recipient can confirm it hasn&rsquo;t changed. Every download is audited.</p>
          <p className="muted" style={{ marginTop: "1rem" }}>Reports describe what RuyaShield observed. They are not a certification or a compliance attestation.</p>
        </Reveal>
        <Reveal>
          <figure className="frame" aria-label="Illustrative example of a report; not live data">
            <div className="frame-bar">
              <span className="frame-title"><span className="frame-dots" aria-hidden="true"><i /><i /><i /></span>ruyashield-report.pdf</span>
              <span className="illus">Illustrative example — not live data</span>
            </div>
            <div className="report-doc">
              <h3>Example Retail — findings report</h3>
              <ul className="rows">
                <li><span className="k">Scope</span><span>3 verified assets</span></li>
                <li><span className="k">Resolved · verified</span><span className="pill pill-ok">With FixProof</span></li>
                <li><span className="k">Open</span><span className="pill pill-warn">Listed with owner and due date</span></li>
              </ul>
              <div className="hash"><span>X-Report-SHA256: </span><span className="hash-v">9f2c…e41a</span> (example)</div>
            </div>
          </figure>
        </Reveal>
      </div>
    </section>
  );
}

function Pricing() {
  const plans = [
    { name: "Developer", who: "For individual developers looking after their own sites.", items: ["Ownership-verified assets", "All four check families", "Zealot explanations", "FixProof verification"] },
    { name: "Agency & MSP", who: "For teams managing security across many client sites.", items: ["Client groups and scoped members", "Approvals with MFA step-up", "Reports with checksums", "Scoped API tokens"], featured: true },
    { name: "SMB", who: "For in-house teams responsible for a handful of sites.", items: ["Owners and due dates on findings", "Regression re-tests on your interval", "Security-critical alerts", "Audit log and kill switch"] },
  ];
  return (
    <section id="pricing" className="section wrap" aria-labelledby="pricing-title">
      <Reveal className="section-head split">
        <div>
          <span className="eyebrow">Pricing</span>
          <h2 id="pricing-title" className="display" style={{ marginTop: "1.25rem" }}>Built for three kinds of <em>teams.</em></h2>
        </div>
        <p className="lead">Pricing hasn&rsquo;t been published yet. Sign in to use RuyaShield with your organization today.</p>
      </Reveal>
      <Reveal className="plans">
        {plans.map((p) => (
          <div key={p.name} className={p.featured ? "plan featured" : "plan"}>
            <h3>{p.name}</h3>
            <p className="who">{p.who}</p>
            <p className="price">Pricing not yet published</p>
            <ul>{p.items.map((i) => <li key={i}>{i}</li>)}</ul>
          </div>
        ))}
      </Reveal>
    </section>
  );
}

function Faq() {
  const qs = [
    ["What will RuyaShield test?", "Only assets your organization has proven it owns, through a DNS TXT record or a hosted file. Checks are non-intrusive: certificate expiry, HTTP security headers, email posture (SPF/DMARC) and CAA records. Nothing intrusive runs automatically."],
    ["Does Zealot decide whether something is a vulnerability?", "No. Zealot explains findings and suggests next steps, citing the evidence it used. People confirm, adjust or dismiss findings, and nothing Zealot says changes a finding. Organizations can switch it off."],
    ["Can Zealot be manipulated by the website it's looking at?", "Content from scanned websites is treated as untrusted data, never as instructions, and secrets are redacted before analysis. Claims without cited evidence are dropped."],
    ["When is a finding marked fixed?", "Only after the original check is re-run and passes. Partial, failed, inconclusive and not-run results are shown as exactly that — none of them resolves a finding."],
    ["Does RuyaShield change my code?", "It can prepare a change on a separate branch in your connected repository after an approval, and test it in a sandbox. It doesn't merge or deploy anything."],
    ["Is a RuyaShield report a certification?", "No. Reports describe what was observed and verified. They are not a certification or a compliance attestation."],
    ["How much does it cost?", "Pricing hasn't been published yet."],
  ];
  return (
    <section id="faq" className="section wrap" aria-labelledby="faq-title">
      <div className="faq-grid">
        <Reveal>
          <span className="eyebrow">FAQ</span>
          <h2 id="faq-title" className="display" style={{ marginTop: "1.25rem" }}>Straight <em>answers.</em></h2>
        </Reveal>
        <Reveal className="faq">
          {qs.map(([q, a]) => <details key={q}><summary>{q}</summary><p>{a}</p></details>)}
        </Reveal>
      </div>
    </section>
  );
}
