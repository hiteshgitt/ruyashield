// Generates the RuyaShield v2.0 deliverables from the data modules.
const fs = require('fs');
const path = require('path');
const ExcelJS = require('exceljs');
const D = require('docx');
const core = require('./data_core.js');
const { stories, DOD } = require('./data_stories.js');
const { T } = require('./data_tests.js');
const X = require('./data_tech.js');

const OUT = process.argv[2] || '/var/www/html/RuyaShield';
const DIAG = path.join(__dirname, 'diagrams');
const { L, meta } = core;

const nextActions = ['Conduct discovery with 15–20 web agencies.', 'Select and validate the first scanner, including licensing and technical coverage.',
  'Create an architecture decision record and threat model.', 'Build the asset, scan, finding, and evidence foundation.', 'Prototype AI investigation and FixProof.',
  'Connect WebMonitor to the authorized assessment workflow.', 'Recruit five pilot organizations and target at least three paid pilots.',
  'Evaluate security quality, remediation time, and commercial viability before expanding scope.'];

// ---------------- Traceability derivation ----------------
const testById = new Map(T.map(t => [t[0], t]));
const gateByPhase = new Map(core.phases.map(p => [p[0], p[6]]));
const storyByTest = new Map();
for (const s of stories) for (const q of s.qa || []) {
  if (!storyByTest.has(q)) storyByTest.set(q, []);
  storyByTest.get(q).push(s.id);
}
const storyById = new Map(stories.map(s => [s.id, s]));
const testGate = t => t[8] || [...new Set((storyByTest.get(t[0]) || []).map(id => gateByPhase.get(storyById.get(id).phase) || '—'))].join(', ') || '—';
const testReqs = t => {
  const r = new Set(t[7] || []);
  for (const sid of storyByTest.get(t[0]) || []) for (const q of storyById.get(sid).reqs) r.add(q);
  return [...r];
};

const allReqIds = [
  ...core.requirements.map(r => r[0]), ...core.secReqs.map(r => r[0]), ...core.releaseBlockers.map(r => r[0]), ...core.nfrs.map(r => r[0]),
];
const reqMeta = new Map();
core.requirements.forEach(r => reqMeta.set(r[0], { kind: 'Functional', title: r[1], priority: r[3], label: r[4], epic: r[5], phase: r[6] }));
core.secReqs.forEach(r => reqMeta.set(r[0], { kind: 'Security', title: r[1], priority: 'P0', label: r[2], epic: '', phase: '' }));
core.releaseBlockers.forEach(r => reqMeta.set(r[0], { kind: 'Release blocker', title: r[1], priority: 'P0', label: r[2], epic: '', phase: '' }));
core.nfrs.forEach(r => reqMeta.set(r[0], { kind: 'Non-functional', title: r[1] + ': ' + r[2], priority: '', label: r[4], epic: '', phase: '' }));

const trace = allReqIds.map(id => {
  const m = reqMeta.get(id);
  const ss = stories.filter(s => s.reqs.includes(id));
  const tests = new Set();
  ss.forEach(s => (s.qa || []).forEach(q => tests.add(q)));
  T.forEach(t => { if ((t[7] || []).includes(id)) tests.add(t[0]); });
  const epics = new Set(ss.map(s => s.epic)); if (m.epic) epics.add(m.epic);
  const gates = new Set();
  ss.forEach(s => gateByPhase.get(s.phase) && gates.add(gateByPhase.get(s.phase)));
  [...tests].forEach(q => { const t = testById.get(q); if (t && t[8]) gates.add(t[8]); });
  if (m.phase && gateByPhase.get(m.phase)) gates.add(gateByPhase.get(m.phase));
  return {
    id, kind: m.kind, title: m.title, priority: m.priority, label: m.label, epics: [...epics].join(', '), stories: ss.map(s => s.id).join(', '),
    api: ss.filter(s => s.api).map(s => s.api).join(' | '), data: ss.filter(s => s.data).map(s => s.data).join(' | '),
    tests: [...tests].sort().join(', '), gates: [...gates].sort().join(', '), testCount: tests.size, storyCount: ss.length,
  };
});

// ---------------- Consistency checks (fail loudly) ----------------
const problems = [];
const epicIds = new Set(core.epics.map(e => e[0]));
const decIds = new Set(core.decisions.map(d => d[0]));
for (const s of stories) {
  if (!epicIds.has(s.epic)) problems.push(`${s.id}: unknown epic ${s.epic}`);
  for (const r of s.reqs) if (!reqMeta.has(r) && !decIds.has(r)) problems.push(`${s.id}: unknown req ${r}`);
  for (const q of s.qa || []) if (!testById.has(q)) problems.push(`${s.id}: unknown test ${q}`);
  if (!gateByPhase.has(s.phase) && s.phase !== 'Later') problems.push(`${s.id}: unknown phase ${s.phase}`);
}
for (const t of T) for (const r of t[7] || []) if (!reqMeta.has(r) && !decIds.has(r)) problems.push(`${t[0]}: unknown req ${r}`);
for (const r of core.requirements) if (!epicIds.has(r[5])) problems.push(`${r[0]}: unknown epic ${r[5]}`);
if (new Set(T.map(t => t[0])).size !== T.length) problems.push('duplicate test IDs');
if (new Set(stories.map(s => s.id)).size !== stories.length) problems.push('duplicate story IDs');
const orphanTests = T.filter(t => !storyByTest.has(t[0]) && !(t[7] || []).length).map(t => t[0]);
if (orphanTests.length) problems.push('tests with no story or requirement: ' + orphanTests.join(', '));
if (problems.length) { console.error(problems.join('\n')); process.exit(1); }

const gapsReq = trace.filter(r => r.testCount === 0);
const gapsStory = stories.filter(s => !(s.qa || []).length);

// ================= DOCX =================
const FONT = 'Calibri';
const PAGE_W = 11906, PAGE_H = 16838, MARGIN = 1134;
const CW = PAGE_W - 2 * MARGIN; // 9638 DXA content width
const NAVY = '1F3864', LIGHT = 'D9E2F3', GREY = 'F2F2F2';
const labelFill = t => !t ? null : t.startsWith(L.Q) ? 'FFF2CC' : t.startsWith(L.R) ? 'DDEBF7' : t.startsWith(L.C) ? 'E2EFDA' : null;
const border = { style: D.BorderStyle.SINGLE, size: 4, color: 'BFBFBF' };
const borders = { top: border, bottom: border, left: border, right: border };

const run = (text, o = {}) => new D.TextRun({ text: String(text), font: o.mono ? 'Consolas' : FONT, size: o.size, bold: o.bold, italics: o.italics, color: o.color });
const P = (text, o = {}) => new D.Paragraph({ children: Array.isArray(text) ? text : [run(text, o)], spacing: { after: o.after ?? 120 }, alignment: o.align, style: o.style });
const H = (lvl, text) => new D.Paragraph({ heading: [D.HeadingLevel.HEADING_1, D.HeadingLevel.HEADING_2, D.HeadingLevel.HEADING_3][lvl - 1], children: [run(text)], pageBreakBefore: lvl === 1 });
const bullets = (items, ref = 'bul') => items.map(t => new D.Paragraph({ numbering: { reference: ref, level: 0 }, children: [run(t)], spacing: { after: 60 } }));
let numInstance = 0;
const numbered = items => { numInstance++; return items.map(t => new D.Paragraph({ numbering: { reference: 'num', level: 0, instance: numInstance }, children: [run(t)], spacing: { after: 60 } })); };
const note = text => new D.Paragraph({ children: [run(text, { italics: true, size: 18, color: '595959' })], spacing: { after: 160 } });

function cellParas(v, size, bold) {
  const lines = Array.isArray(v) ? v : String(v ?? '').split('\n');
  return lines.map(l => new D.Paragraph({ children: [run(l, { size, bold })], spacing: { after: 0 } }));
}
function table(headers, rows, ratios, o = {}) {
  const size = o.size || 16;
  const tot = ratios.reduce((a, b) => a + b, 0);
  const widths = ratios.map(r => Math.floor(CW * r / tot));
  widths[widths.length - 1] += CW - widths.reduce((a, b) => a + b, 0);
  const mk = (v, i, hdr, fill) => new D.TableCell({
    width: { size: widths[i], type: D.WidthType.DXA }, borders,
    margins: { top: 40, bottom: 40, left: 80, right: 80 },
    shading: hdr ? { type: D.ShadingType.CLEAR, color: 'auto', fill: NAVY } : fill ? { type: D.ShadingType.CLEAR, color: 'auto', fill } : undefined,
    children: hdr ? [new D.Paragraph({ children: [run(v, { size, bold: true, color: 'FFFFFF' })] })] : cellParas(v, size, o.boldFirst && i === 0),
  });
  const labelCol = o.labelCol;
  return new D.Table({
    width: { size: CW, type: D.WidthType.DXA }, columnWidths: widths,
    rows: [
      new D.TableRow({ tableHeader: true, children: headers.map((h, i) => mk(h, i, true)) }),
      ...rows.map((r, ri) => new D.TableRow({ cantSplit: o.cantSplit, children: r.map((v, i) => mk(v, i, false, i === labelCol ? labelFill(String(v)) : (o.stripe && ri % 2 ? GREY : null))) })),
    ],
  });
}
const kv = (pairs, ratio = [1, 3.2]) => table(['Field', 'Detail'], pairs.filter(p => p[1] !== undefined && p[1] !== '' && !(Array.isArray(p[1]) && !p[1].length)), ratio, { boldFirst: true });
const gap = () => new D.Paragraph({ children: [], spacing: { after: 120 } });

function image(file, caption, maxH = 820) {
  const buf = fs.readFileSync(path.join(DIAG, file));
  const w0 = buf.readUInt32BE(16), h0 = buf.readUInt32BE(20);
  const maxW = Math.floor(CW / 15); // DXA → px at 96 dpi
  let w = maxW, h = Math.round(h0 * maxW / w0);
  if (h > maxH) { h = maxH; w = Math.round(w0 * maxH / h0); }
  return [
    new D.Paragraph({ alignment: D.AlignmentType.CENTER, children: [new D.ImageRun({ type: 'png', data: buf, transformation: { width: w, height: h }, altText: { title: caption, description: caption, name: file } })] }),
    new D.Paragraph({ alignment: D.AlignmentType.CENTER, children: [run(caption, { italics: true, size: 18 })], spacing: { after: 200 } }),
  ];
}
const code = text => text.split('\n').map((l, i, a) => new D.Paragraph({
  children: [run(l || ' ', { mono: true, size: 16 })], spacing: { after: i === a.length - 1 ? 160 : 0 },
  shading: { type: D.ShadingType.CLEAR, color: 'auto', fill: GREY },
}));

const body = [];
const add = (...xs) => xs.flat().forEach(x => body.push(x));

// ---- Cover ----
const cover = [
  new D.Paragraph({ children: [], spacing: { before: 2400 } }),
  P([run('RuyaShield', { size: 72, bold: true, color: NAVY })], { align: D.AlignmentType.CENTER }),
  P([run('Product Requirements Document v2.0', { size: 40, color: NAVY })], { align: D.AlignmentType.CENTER }),
  P([run('Implementation-ready specification', { size: 28, italics: true })], { align: D.AlignmentType.CENTER, after: 600 }),
  P([run(`A ${meta.parent} product · Version ${meta.version} · ${meta.date}`, { size: 24 })], { align: D.AlignmentType.CENTER }),
  P([run(`Status: ${meta.status}`, { size: 22 })], { align: D.AlignmentType.CENTER }),
  P([run(`Owner: ${meta.owner}`, { size: 22 })], { align: D.AlignmentType.CENTER, after: 1200 }),
  P([run('This document is an AI-assisted draft derived from RuyaShield PRD v1.1. It needs review and sign-off by the product owner, technical lead and security engineer before it is used as a build contract. It makes no certification or compliance claim, and it describes no completed implementation work.', { size: 20, italics: true, color: '595959' })], { align: D.AlignmentType.CENTER }),
  new D.Paragraph({ children: [new D.PageBreak()] }),
  P([run('Version history', { size: 32, bold: true, color: NAVY })]),
  table(['Version', 'Date', 'Summary', 'Author'], meta.history, [1, 1.4, 5, 1.6]),
  gap(),
  P([run('Labels used in this document', { size: 28, bold: true, color: NAVY })]),
  table(['Label', 'Meaning'], [
    [L.C, 'Stated in, or directly derived from, RuyaShield PRD v1.1.'],
    [L.R, 'Added in v2.0 to make the specification buildable and testable. Needs product/tech sign-off.'],
    [L.Q, 'Cannot be resolved from the source; owner and deadline in the Decision Log (§22).'],
  ], [1.5, 4], { labelCol: 0 }),
  note('Numbers that are not in v1.1 (timeouts, limits, retention, NFR details) are marked as assumptions and are provisional until validated.'),
  new D.Paragraph({ children: [new D.PageBreak()] }),
  P([run('Contents', { size: 32, bold: true, color: NAVY })]),
  new D.TableOfContents('Contents', { hyperlink: true, headingStyleRange: '1-2' }),
  note('If the table of contents is empty, right-click it in Word and choose "Update Field".'),
];

// ---- 1 Introduction & strategy ----
add(H(1, '1 Introduction and product strategy'));
add(H(2, '1.1 Purpose of this document'));
add(P('This PRD v2.0 turns RuyaShield PRD v1.1 into an implementation-ready specification. It covers the audit, requirements, roles, epics and stories, workflows, AI/FixProof/WebMonitor specifications, technical blueprint, QA plan, implementation plan and traceability. Companion files: RuyaShield_Product_Backlog.xlsx, RuyaShield_Technical_Blueprint.md, RuyaShield_QA_Test_Plan.xlsx and RuyaShield_Requirements_Traceability.xlsx. All of them are generated from the same source data.'));
add(H(2, '1.2 Vision, positioning and principles'));
add(table(['Item', 'Statement', 'Label'], [['Vision', X.vision.vision, X.vision.visionLabel], ['Positioning', X.vision.positioning, X.vision.positioningLabel]], [1, 5, 1.6], { labelCol: 2 }));
add(gap(), P('Product principles (v1.1 Appendix A, ' + L.C + '):', { bold: true }), bullets(X.vision.principles));
add(H(2, '1.3 Problem'));
add(bullets(X.vision.problems));
add(H(2, '1.4 Personas'));
add(table(['Type', 'Persona', 'Needs', 'Typical role', 'Label'], X.personas, [1, 1.8, 3.6, 1.6, 1.4], { labelCol: 4 }));
add(H(2, '1.5 Scope and non-goals'));
add(table(['Capability', 'In scope', 'Label'], X.scopeIn, [1.6, 4.4, 1.6], { labelCol: 2 }));
add(gap(), P('Out of scope / non-goals', { bold: true }));
add(table(['Exclusion', 'Label'], X.scopeOut, [5, 1.6], { labelCol: 1 }));
add(H(2, '1.6 Business objectives and success metrics'));
add(table(['ID', 'Objective', 'Measure', 'Label'], X.objectives, [0.8, 2, 4, 1.4], { labelCol: 3 }));
add(gap());
add(table(['Metric', 'Target', 'Measurement', 'Label'], X.metrics, [2, 1.6, 3.6, 1.4], { labelCol: 3 }));
add(H(2, '1.7 Facts versus assumptions'));
add(P('Facts (from v1.1)', { bold: true }), bullets(core.factsVsAssumptions.facts));
add(P('Assumptions (to validate)', { bold: true }), bullets(core.factsVsAssumptions.assumptions));

// ---- 2 Audit ----
add(H(1, '2 PRD v1.1 audit'));
add(P(`The audit found ${core.audit.length} issues in v1.1. Each one is resolved in v2.0 or carried into the Decision Log. Severity shows how much each gap would block implementation or testing.`));
const sevCount = {}; core.audit.forEach(a => sevCount[a[5]] = (sevCount[a[5]] || 0) + 1);
add(table(['Severity', 'Count'], Object.entries(sevCount), [3, 1]));
add(gap());
add(table(['ID', 'Area', 'Observation', 'Impact', 'Resolution in v2.0', 'Sev.'], core.audit, [0.8, 1.1, 2.6, 2.2, 2.8, 0.7], { size: 15 }));

// ---- 3 Requirements ----
add(H(1, '3 Requirements'));
add(H(2, '3.1 Functional requirements'));
add(P('All v1.1 FR IDs are kept. Gaps in the v1.1 numbering are used for new requirements, and FR-047…FR-049 are unused. Appendix C maps v1.1 sections to v2.0.'));
add(table(['ID', 'Title', 'Statement', 'Pri', 'Label', 'Epic', 'Phase'], core.requirements, [0.8, 1.5, 3.6, 0.5, 1.4, 0.8, 0.6], { labelCol: 4, size: 15 }));
add(H(2, '3.2 Security requirements'));
add(table(['ID', 'Requirement', 'Label'], core.secReqs, [0.8, 5.2, 1.6], { labelCol: 2 }));
add(H(2, '3.3 Release blockers'));
add(table(['ID', 'Blocker', 'Label'], core.releaseBlockers, [0.8, 5.2, 1.6], { labelCol: 2 }));

// ---- 4 Roles ----
add(H(1, '4 Roles and permissions'));
add(H(2, '4.1 Roles'));
add(table(['Key', 'Role', 'Responsibilities', 'Auth'], core.roles, [1.2, 1.2, 4.6, 1.1]));
add(H(2, '4.2 Separation of duties'));
add(bullets([
  'An approver cannot approve their own request. A single-approver policy (D-08) is an org-level, audited exception, and it still forbids approving your own request.',
  'Every approval needs step-up authentication (auth_time ≤ 15 min) and is bound to the exact content hash.',
  'Enabling A2 checks needs two people. A2 is flag-off for the MVP.',
  'Platform operators have no standing access to tenant data. Break-glass access requires a reason, is time-limited, and is audited.',
  'The service identity performs only system transitions such as resolved_verified and can never approve.',
]));
add(H(2, '4.3 Permission matrix'));
add(table(['Area', 'Action', ...core.permCols], core.permissions, [1.0, 1.8, 0.95, 1.2, 0.75, 0.85, 0.85, 0.7, 1.0], { size: 13, stripe: true, cantSplit: true }));
add(note(core.permLegend));

// ---- 5 Epics ----
add(H(1, '5 Epics'));
add(table(['ID', 'Epic', 'Priority', 'Phase', 'Objective'], core.epics.map(e => [e[0], e[1], e[7], e[10], e[2]]), [0.9, 2, 0.8, 0.7, 4.2]));
for (const e of core.epics) {
  add(H(3, `${e[0]} — ${e[1]}`));
  add(kv([['Objective', e[2]], ['Problem', e[3]], ['Scope', e[4]], ['Non-goals', e[5]], ['Dependencies', e[6]], ['Priority / phase', `${e[7]} / ${e[10]}`], ['Measurable outcome', e[8]], ['Risks', e[9]],
    ['Stories', stories.filter(s => s.epic === e[0]).map(s => s.id).join(', ')]]));
}

// ---- 6 Workflows ----
add(H(1, '6 Workflows and state machines'));
add(P('Every transition is enforced on the server by one state-machine module. Any transition outside these tables returns 422 transition_not_allowed and writes an audit event. Each transition is tagged with its action type:'));
add(table(['Code', 'Action type', 'Meaning'], X.actionTypes, [0.6, 1.8, 5]));
const tHead = ['From', 'To', 'Trigger / guard', 'Actor', 'Type'];
const tRat = [1.5, 1.6, 3.6, 1.6, 0.7];
add(H(2, '6.1 Assessment lifecycle'));
add(image('assessment_sm.png', 'Figure 6-1 Assessment state machine', 560));
add(table(tHead, X.transitions.assessment, tRat));
add(gap(), ...image('assessment_flow.png', 'Figure 6-2 Assessment launch pre-checks'));
add(H(2, '6.2 Finding lifecycle'));
add(image('finding_sm.png', 'Figure 6-3 Finding state machine', 640));
add(table(tHead, X.transitions.finding, tRat));
add(H(2, '6.3 Remediation lifecycle'));
add(image('remediation_sm.png', 'Figure 6-4 Remediation state machine', 760));
add(table(tHead, X.transitions.remediation, tRat));
add(H(2, '6.4 Approval lifecycle'));
add(image('approval_sm.png', 'Figure 6-5 Approval state machine'));
add(table(tHead, X.transitions.approval, tRat));
add(H(2, '6.5 Verification, FixProof and asset verification'));
add(image('verification_sm.png', 'Figure 6-6 Verification run state machine'));
add(table(tHead, X.transitions.verification, tRat));
add(gap(), P('Asset verification', { bold: true }));
add(table(tHead, X.transitions.asset, tRat));
add(H(2, '6.6 End-to-end journeys'));
add(table(['ID', 'Journey', 'Steps', 'Epics', 'Phase', 'Label'], X.journeys, [0.6, 1.4, 4, 1.3, 1.3, 1.3], { labelCol: 5, size: 15 }));
add(gap(), ...image('remediation_seq.png', 'Figure 6-7 Remediation to pull request (sequence)'));

// ---- 7 Stories ----
add(H(1, '7 User stories'));
const full = stories.filter(s => s.tpl === 'Full'), light = stories.filter(s => s.tpl !== 'Full');
add(P(`${stories.length} stories: ${full.length} use the full template (P0/P1) and ${light.length} use the light template (P2/P3 and later). Acceptance criteria use Given/When/Then. Every story also has to meet the Definition of Done in §15.4. The template is in Appendix B.`));
add(H(2, '7.1 Full-template stories'));
for (const s of full) {
  add(H(3, `${s.id} ${s.title}`));
  add(kv([
    ['Story', s.story], ['Business value', s.value], ['Epic / phase / priority', `${s.epic} / ${s.phase} / ${s.priority}`], ['Requirements', s.reqs.join(', ')], ['Dependencies', s.deps],
    ['Preconditions', s.pre], ['Main flow', s.flow.map((f, i) => `${i + 1}. ${f}`)], ['Alternate / error flows', s.alt.map(a => '– ' + a)],
    ['Acceptance criteria', s.ac.map((a, i) => `AC${i + 1}. ${a}`)], ['Security & privacy', s.sec], ['Data', s.data], ['API', s.api], ['Observability & audit', s.obs],
    ['QA test cases', (s.qa || []).join(', ') || 'None yet (see coverage gaps)'],
  ]));
}
add(H(2, '7.2 Light-template stories'));
add(table(['ID', 'Epic', 'Ph.', 'Pri', 'Story', 'Acceptance criteria', 'Tests'],
  light.map(s => [s.id, s.epic, s.phase, s.priority, `${s.title}. ${s.story}`, (s.ac || []).map((a, i) => `AC${i + 1}. ${a}`), (s.qa || []).join(', ') || '—']),
  [1.1, 0.7, 0.55, 0.45, 2.8, 3.2, 0.9], { size: 15 }));

// ---- 8 AI ----
add(H(1, '8 AI specification'));
add(P('AI is an assistive layer. With AI switched off, the core workflow (authorize → assess → finding → remediation → approval → verification → FixProof) still runs end to end. The model receives redacted data and returns schema-validated JSON. It has no tools, no network access and no ability to change state.'));
add(H(2, '8.1 Use cases: optional, required, prohibited'));
add(table(['ID', 'Use case', 'Status', 'Inputs', 'Output', 'Fallback / enforcement', 'Story'], X.aiUseCases, [0.8, 1.8, 0.9, 1.7, 1.5, 2, 0.9], { size: 15 }));
add(H(2, '8.2 Output typing'));
add(table(['Type', 'Definition', 'Validation rule'], X.aiClaimTypes, [1.1, 3, 3.5]));
add(H(2, '8.3 Controls'));
add(table(['Control', 'Specification', 'Label'], X.aiControls, [1.3, 4.8, 1.5], { labelCol: 2 }));
add(H(2, '8.4 v1.1 prohibited AI actions (preserved)'));
add(P('Confirmed from existing PRD (v1.1 §6.2, verbatim). AI must not:'));
add(bullets(['Claim compromise without adequate evidence.', 'Execute arbitrary shell commands or unrestricted tool calls.', 'Expand scans beyond the authorized scope.', 'Exfiltrate data or secrets.', 'Modify production without required human approval.', 'Mark a finding resolved solely on the model\'s assertion.', 'Claim complete security or guaranteed protection.']));
add(P('Recommended addition. These follow from ADR-006/ADR-008 and are enforced outside the model:'));
add(bullets(['Run destructive or high-impact (A2/X) checks, or launch any scan itself.', 'Merge or deploy code (RuyaShield opens pull requests only).', 'Treat website, repository, log or upload content as instructions.', 'Present failed, inconclusive, error or not_run verification as passed.']));

// ---- 9 FixProof ----
add(H(1, '9 FixProof specification'));
add(image('fixproof_seq.png', 'Figure 9-1 Verification to FixProof (sequence)'));
add(H(2, '9.1 Contents'));
add(table(['Section', 'Fields'], X.fixproofContents, [1.4, 5.6]));
add(H(2, '9.2 Status mapping'));
add(table(['Verification run results', 'FixProof status', 'Finding outcome', 'Note'], X.fixproofStatus, [2.6, 1.4, 2, 2]));
add(H(2, '9.3 Rules: integrity, export, retention, reopen'));
add(bullets(X.fixproofRules));

// ---- 10 WebMonitor ----
add(H(1, '10 WebMonitor integration (provisional)'));
add(P('WebMonitor is an acquisition and integration channel. This section defines only a RuyaShield-side adapter. No WebMonitor endpoint, payload or authentication method is assumed to exist until DEP-WM-01 is resolved.'));
add(table(['Aspect', 'Specification', 'Label'], X.wmAdapter, [1.2, 4.9, 1.5], { labelCol: 2 }));
add(gap(), P('Provisional adapter interface (TypeScript, illustrative):', { bold: true }), code(X.wmInterface));

// ---- 11 Architecture ----
add(H(1, '11 Architecture'));
add(H(2, '11.1 System context'));
add(image('context.png', 'Figure 11-1 System context', 700));
add(H(2, '11.2 Containers'));
add(image('containers.png', 'Figure 11-2 Containers and deployment units', 880));
add(H(2, '11.3 Trust boundaries'));
add(image('trust.png', 'Figure 11-3 Trust boundaries'));
add(table(['ID', 'Boundary', 'Data crossing', 'Controls'], X.trustBoundaries, [0.6, 2, 1.8, 3.8]));
add(H(2, '11.4 Modules (modular monolith)'));
add(table(['Module', 'Responsibility', 'Runs in', 'Epics'], X.modules, [1.2, 4, 1.6, 1.2]));
add(H(2, '11.5 Architecture decision records'));
add(table(['ADR', 'Title', 'Decision', 'Rationale', 'Consequences', 'Status', 'Label'], X.adrs, [0.75, 1.3, 2.3, 1.5, 1.6, 0.9, 1.1], { size: 14, labelCol: 6 }));
add(H(2, '11.6 Sandbox specification'));
add(table(['Aspect', 'Specification', 'Label'], X.sandbox, [1.2, 4.8, 1.5], { labelCol: 2 }));
add(H(2, '11.7 Egress guard rules'));
add(bullets(X.egress));

// ---- 12 Data ----
add(H(1, '12 Data model'));
add(H(2, '12.1 Entity relationship overview'));
add(image('erd.png', 'Figure 12-1 Core entities'));
add(H(2, '12.2 Tables'));
add(table(['Table', 'Purpose', 'Key columns', 'Tenancy', 'Retention (assumption)'], X.tables, [1.5, 1.4, 3.6, 1.1, 1.3], { size: 14, stripe: true }));
add(H(2, '12.3 Retention'));
add(table(['Data', 'Retention', 'Reason', 'Label'], X.retention, [2, 2.6, 1.4, 2], { labelCol: 3 }));
add(H(2, '12.4 Audit event catalogue'));
add(P('Each audit event records org_id, actor (user, service or operator), action, subject, outcome, IP/user agent where relevant, timestamp, prev_hash and hash. Audit events can only be inserted, never updated.'));
add(table(['Event types', 'Epic'], X.auditCatalogue, [5, 1.5]));

// ---- 13 API ----
add(H(1, '13 API and event contracts (proposed)'));
add(H(2, '13.1 Conventions'));
add(bullets(X.apiConventions));
add(H(2, '13.2 Endpoints'));
add(table(['Method', 'Path', 'Purpose', 'Roles', 'Story'], X.api, [0.7, 3, 2.2, 1.7, 1.1], { size: 15 }));
add(H(2, '13.3 JSON examples'));
for (const [t, c] of X.jsonExamples) add(P(t, { bold: true }), code(c));
add(H(2, '13.4 Domain events'));
add(table(['Event', 'Producer', 'Consumers', 'Key payload'], X.events, [2.2, 1.3, 2, 2.6]));
add(gap(), P('Event envelope', { bold: true }), code(X.eventEnvelope));

// ---- 14 UX ----
add(H(1, '14 UX screens'));
add(table(['ID', 'Screen', 'Primary roles', 'Key content', 'Edge states'], X.screens, [0.6, 1.6, 1.4, 3.2, 2]));
add(H(2, '14.1 UX rules'));
add(bullets(X.uxRules));

// ---- 15 QA ----
add(H(1, '15 QA and security test plan'));
add(H(2, '15.1 Test strategy'));
add(table(['Level', 'Scope', 'When', 'Tooling'], X.qaStrategy, [1.1, 3.8, 1.6, 1.8]));
add(note('All security testing targets RuyaShield\'s own lab assets and environments only. No test is ever run against customer or third-party systems.'));
add(H(2, '15.2 Environments'));
add(table(['Environment', 'Purpose'], X.environments, [1.4, 5]));
add(H(2, '15.3 Test catalogue summary'));
const byType = {}; T.forEach(t => byType[t[1]] = (byType[t[1]] || 0) + 1);
add(P(`${T.length} test cases in RuyaShield_QA_Test_Plan.xlsx. By type: ${Object.entries(byType).map(([k, v]) => `${k} ${v}`).join(', ')}.`));
const prefix = id => id.split('-')[1];
const byArea = {}; T.forEach(t => { const a = prefix(t[0]); byArea[a] = byArea[a] || { n: 0, p0: 0, neg: 0 }; byArea[a].n++; if (t[2] === 'P0') byArea[a].p0++; if (t[1] === 'negative' || t[1] === 'security') byArea[a].neg++; });
add(table(['Area', 'Tests', 'P0', 'Negative + security'], Object.entries(byArea).map(([a, v]) => [a, v.n, v.p0, v.neg]), [2, 1, 1, 1.5]));
add(H(2, '15.4 Definition of Done'));
add(P('v1.1 Definition of Done (' + L.C + '):', { bold: true }), bullets(X.dodV11));
add(P('Additions in v2.0 (' + L.R + '):', { bold: true }), bullets(X.dodAdd));
add(note('Story-level shorthand: ' + DOD));
add(H(2, '15.5 Test case index'));
add(table(['ID', 'Type', 'Pri', 'Title', 'Expected result', 'Gate'], T.map(t => [t[0], t[1], t[2], t[3], t[6], testGate(t)]), [1.2, 0.8, 0.45, 2.2, 3.6, 0.6], { size: 14, stripe: true }));

// ---- 16 Gates & NFRs ----
add(H(1, '16 Release gates and non-functional requirements'));
add(H(2, '16.1 Release blockers and their tests'));
add(table(['ID', 'Blocker', 'Tests'], core.releaseBlockers.map(r => [r[0], r[1], trace.find(x => x.id === r[0]).tests || '—']), [0.8, 3.6, 3]));
add(H(2, '16.2 Phase gates'));
add(table(['Phase', 'Gate', 'Exit criteria'], core.phases.map(p => [`${p[0]} ${p[1]}`, p[6], p[7]]), [1.6, 0.6, 5.4]));
add(H(2, '16.3 Non-functional requirements'));
add(table(['ID', 'Category', 'Target', 'Measurement', 'Label'], core.nfrs, [0.8, 1.2, 2.8, 2.4, 1.4], { labelCol: 4, size: 15 }));

// ---- 17 Roadmap ----
add(H(1, '17 Implementation plan and roadmap'));
add(P('P0 is discovery and validation before any build work. P1–P8 are the delivery phases. T-shirt sizes are relative effort for the team in §18 and are not commitments: S ≈ 1–2 weeks, M ≈ 3–4, L ≈ 5–8, XL > 8 (assumption).'));
add(table(['Phase', 'Name', 'Size', 'Objective', 'Deliverables', 'Epics', 'Gate'], core.phases.map(p => p.slice(0, 7)), [0.5, 1.2, 0.5, 1.6, 3.2, 1.1, 0.5], { size: 15 }));
add(H(2, '17.1 Smallest coherent MVP'));
add(bullets(core.mvpDefinition));
add(H(2, '17.2 Phase dependencies'));
add(P(core.phaseDeps.map(d => `${d[0]} → ${d[1]}`).join('; ') + '.'));
add(H(2, '17.3 Immediate next actions (v1.1 §19, preserved; Phase P0)'));
add(numbered(nextActions));

// ---- 18 Ops & commercial ----
add(H(1, '18 Operations, team and commercial model'));
add(H(2, '18.1 Team'));
add(table(['Role', 'Responsibility', 'Label'], X.team, [2, 4.5, 1.5], { labelCol: 2 }));
add(H(2, '18.2 Pricing hypotheses'));
add(P('These are v1.1 hypotheses (' + L.C + ') to be validated in discovery. The MVP includes no billing or payment integration: pilots are invoiced manually and quotas are enforced in-product. Prices are in INR per month.'));
add(table(['Plan', 'Price (hypothesis)', 'Positioning'], X.pricing, [1.5, 1.6, 4]));
add(H(2, '18.3 KPIs'));
add(table(['Category', 'KPIs', 'Label'], X.kpis, [1.2, 5, 1.5], { labelCol: 2 }));
add(H(2, '18.4 Operations'));
add(table(['Area', 'Plan', 'Label'], X.ops, [1.4, 4.8, 1.5], { labelCol: 2 }));

// ---- 19 Risks ----
add(H(1, '19 Risks'));
add(table(['ID', 'Risk', 'Severity', 'Mitigation', 'Label'], core.risks, [0.7, 2, 0.8, 3.6, 1.4], { labelCol: 4 }));

// ---- 20 Traceability ----
add(H(1, '20 Traceability summary'));
add(P(`The full matrix (Requirement → Epic → Story → API/Data → Test → Gate) is in RuyaShield_Requirements_Traceability.xlsx. ${trace.length} requirements are traced, ${trace.filter(r => r.testCount).length} of them have at least one test, and ${gapsReq.length} have no test yet. ${gapsStory.length} stories have no test yet. All of them use the light template and none is P0; tests are written when they are refined, before their phase gate.`));
add(table(['Requirement', 'Epic(s)', 'Stories', 'Tests', 'Gate'], trace.filter(r => r.kind !== 'Non-functional').map(r => [r.id, r.epics || '—', r.stories || '—', r.tests || '—', r.gates || '—']), [0.9, 0.9, 2.6, 3, 0.7], { size: 14, stripe: true }));
add(gap(), P('Coverage gaps', { bold: true }));
add(table(['Item', 'Kind', 'Reason / plan'], [
  ...gapsReq.map(r => [r.id, r.kind, `${r.title}. No test case yet; add before the gate where it applies.`]),
  ...gapsStory.map(s => [s.id, 'Story', `${s.phase} / ${s.priority}: tests to be written when the story is refined.`]),
], [1.2, 1.3, 5]));

// ---- 21 Consistency audit ----
add(H(1, '21 Final consistency audit'));
add(table(['ID', 'Check', 'Finding', 'Result'], X.consistency, [0.7, 1.4, 4.6, 1.3]));
add(note(`Automated checks run by the generator: every story references a known epic, requirement and test; every test maps to a story or requirement; IDs are unique. Results: ${stories.length} stories, ${T.length} tests, ${trace.length} requirements, 0 dangling references.`));

// ---- 22 Decision log ----
add(H(1, '22 Decision log'));
add(P('Decisions are ordered by the gate that needs them. Recommendations are defaults that can be overridden; none is final until the owner signs it off.'));
const gateOrder = g => { const m = /G(\d)(a?)/.exec(g || ''); return m ? +m[1] + (m[2] ? 0.5 : 0) - (m[2] ? 1 : 0) : 99; };
const decSorted = [...core.decisions].sort((a, b) => gateOrder(a[5]) - gateOrder(b[5]));
add(table(['ID', 'Decision', 'Recommendation', 'Label', 'Owner', 'Needed by', 'Impact'], decSorted, [0.6, 1.3, 3, 1.1, 1.2, 0.8, 1.4], { labelCol: 3, size: 14 }));
add(H(2, '22.1 v1.1 decisions carried forward'));
add(table(['Decision', 'v1.1 recommendation'], X.v11Decisions, [2, 5]));

// ---- Appendices ----
add(H(1, 'Appendix A Glossary'));
add(table(['Term', 'Definition'], core.glossary, [1.6, 5.4]));
add(H(1, 'Appendix B Story template and Definition of Done'));
add(table(['Field', 'Full template (P0/P1)', 'Light template (P2/P3)'], [
  ['ID, title, epic', 'Yes', 'Yes'], ['Requirements, phase, priority, dependencies', 'Yes', 'Yes'], ['User story', 'Yes', 'Yes'],
  ['Business value, preconditions', 'Yes', '—'], ['Main flow, alternate/error flows', 'Yes', '—'], ['Acceptance criteria (Given/When/Then)', 'Yes', 'Yes'],
  ['Security & privacy, data, API, observability', 'Yes', '—'], ['QA test cases', 'Yes', 'Yes (may be empty until refined)'],
], [3, 2, 2]));
add(gap(), P('Definition of Done: see §15.4.'));
add(H(1, 'Appendix C v1.1 preservation map'));
add(P('Every section of v1.1 maps to a section of v2.0. No v1.1 requirement has been dropped.'));
add(table(['v1.1 section', 'v2.0 location', 'Treatment'], X.preservation, [2.4, 2.6, 2.6]));

const doc = new D.Document({
  creator: 'RuyaShield Product & Engineering', title: 'RuyaShield PRD v2.0', description: 'Implementation-ready PRD',
  features: { updateFields: true },
  styles: {
    default: { document: { run: { font: FONT, size: 20 } } },
    paragraphStyles: [
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 32, bold: true, color: NAVY }, paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 26, bold: true, color: NAVY }, paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 } },
      { id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 22, bold: true, color: '2F5496' }, paragraph: { spacing: { before: 200, after: 80 }, outlineLevel: 2, keepNext: true } },
    ],
  },
  numbering: { config: [
    { reference: 'bul', levels: [{ level: 0, format: D.LevelFormat.BULLET, text: '•', alignment: D.AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] },
    { reference: 'num', levels: [{ level: 0, format: D.LevelFormat.DECIMAL, text: '%1.', alignment: D.AlignmentType.LEFT, style: { paragraph: { indent: { left: 540, hanging: 360 } } } }] },
  ] },
  sections: [
    { properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN } } }, children: cover },
    {
      properties: { page: { size: { width: PAGE_W, height: PAGE_H }, margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN }, pageNumbers: { start: 1 } } },
      headers: { default: new D.Header({ children: [P([run('RuyaShield PRD v2.0 — implementation-ready specification (draft for review)', { size: 16, color: '808080' })], { align: D.AlignmentType.RIGHT })] }) },
      footers: { default: new D.Footer({ children: [new D.Paragraph({ alignment: D.AlignmentType.CENTER, children: [new D.TextRun({ children: ['Page ', D.PageNumber.CURRENT, ' of ', D.PageNumber.TOTAL_PAGES], size: 16, font: FONT })] })] }) },
      children: body,
    },
  ],
});

// ================= XLSX =================
function sheet(wb, name, headers, rows, widths, o = {}) {
  const ws = wb.addWorksheet(name, { views: [{ state: 'frozen', ySplit: 1 }] });
  ws.columns = headers.map((h, i) => ({ header: h, width: widths[i] || 20 }));
  rows.forEach(r => ws.addRow(r.map(v => Array.isArray(v) ? v.join('\n') : v)));
  const hr = ws.getRow(1);
  hr.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  hr.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF' + NAVY } };
  hr.alignment = { vertical: 'middle', wrapText: true };
  ws.eachRow((row, n) => { if (n > 1) row.alignment = { vertical: 'top', wrapText: true }; });
  ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: headers.length } };
  if (o.labelCol !== undefined) ws.getColumn(o.labelCol + 1).eachCell((c, n) => {
    const f = n > 1 && labelFill(String(c.value || ''));
    if (f) c.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF' + f } };
  });
  return ws;
}
function readme(wb, title, lines) {
  const ws = wb.addWorksheet('README');
  ws.getColumn(1).width = 120;
  ws.addRow([title]).font = { bold: true, size: 14, color: { argb: 'FF' + NAVY } };
  ws.addRow([`Version ${meta.version} · ${meta.date} · generated from the same source data as RuyaShield_PRD_v2.0_Implementation_Ready.docx`]);
  ws.addRow(['AI-assisted draft. Needs product, engineering and security review before use as a build contract.']).font = { italic: true };
  ws.addRow([]);
  lines.forEach(l => ws.addRow([l]).alignment = { wrapText: true });
  ws.addRow([]);
  ws.addRow([`Labels: "${L.C}" (green), "${L.R}" (blue), "${L.Q}" (amber).`]);
}

async function buildXlsx() {
  // Backlog
  const b = new ExcelJS.Workbook();
  readme(b, 'RuyaShield Product Backlog', ['Sheets: Epics, Stories, Requirements, Decisions, Phases, Risks.', `${core.epics.length} epics, ${stories.length} stories (${full.length} full template, ${light.length} light), ${core.requirements.length} functional requirements.`, 'Story order = phase then epic. Acceptance criteria use Given/When/Then.']);
  sheet(b, 'Epics', ['ID', 'Name', 'Objective', 'Problem', 'Scope', 'Non-goals', 'Dependencies', 'Priority', 'Measurable outcome', 'Risks', 'Phase', 'Stories'],
    core.epics.map(e => [...e, stories.filter(s => s.epic === e[0]).map(s => s.id).join(', ')]), [8, 24, 36, 36, 44, 30, 16, 8, 36, 30, 7, 40]);
  const phaseRank = p => p === 'Later' ? 99 : +p.slice(1);
  const ordered = [...stories].sort((a, c) => phaseRank(a.phase) - phaseRank(c.phase) || a.epic.localeCompare(c.epic) || a.id.localeCompare(c.id));
  sheet(b, 'Stories', ['ID', 'Epic', 'Title', 'Template', 'Phase', 'Priority', 'Requirements', 'Dependencies', 'User story', 'Business value', 'Preconditions', 'Main flow', 'Alternate / error flows', 'Acceptance criteria', 'Security & privacy', 'Data', 'API', 'Observability', 'QA tests', 'Gate', 'Definition of Done'],
    ordered.map(s => [s.id, s.epic, s.title, s.tpl, s.phase, s.priority, s.reqs.join(', '), s.deps || '', s.story, s.value || '', s.pre || '',
      (s.flow || []).map((f, i) => `${i + 1}. ${f}`), (s.alt || []).map(a => '- ' + a), (s.ac || []).map((a, i) => `AC${i + 1}. ${a}`), s.sec || '', s.data || '', s.api || '', s.obs || '',
      (s.qa || []).join(', '), gateByPhase.get(s.phase) || '—', DOD]),
    [13, 8, 30, 8, 7, 8, 20, 16, 40, 30, 30, 50, 44, 60, 36, 30, 30, 30, 20, 6, 30]);
  sheet(b, 'Requirements', ['ID', 'Title', 'Statement', 'Priority', 'Label', 'Epic', 'Phase', 'Stories'],
    core.requirements.map(r => [...r, stories.filter(s => s.reqs.includes(r[0])).map(s => s.id).join(', ')]), [9, 28, 60, 8, 26, 8, 7, 34], { labelCol: 4 });
  sheet(b, 'Security reqs', ['ID', 'Requirement', 'Label'], core.secReqs, [8, 90, 28], { labelCol: 2 });
  sheet(b, 'Decisions', ['ID', 'Decision', 'Recommendation', 'Label', 'Owner', 'Needed by', 'Impact'], decSorted, [7, 30, 70, 22, 24, 10, 30], { labelCol: 3 });
  sheet(b, 'Phases', ['ID', 'Name', 'Size', 'Objective', 'Deliverables', 'Epics', 'Gate', 'Exit criteria'], core.phases, [6, 22, 6, 36, 60, 24, 6, 60]);
  sheet(b, 'Risks', ['ID', 'Risk', 'Severity', 'Mitigation', 'Label'], core.risks, [7, 34, 9, 70, 28], { labelCol: 4 });
  await b.xlsx.writeFile(path.join(OUT, 'RuyaShield_Product_Backlog.xlsx'));

  // QA
  const q = new ExcelJS.Workbook();
  readme(q, 'RuyaShield QA and Security Test Plan', [`${T.length} test cases. Types: ${Object.entries(byType).map(([k, v]) => `${k} ${v}`).join(', ')}.`,
    'Status column is blank: no test has been executed, because the application has not been built yet.',
    'All security tests run only against RuyaShield-owned lab targets and environments, never against customer or third-party systems.',
    'Sheets: Tests, Release Blockers, AI Eval, Strategy, Environments, Definition of Done.']);
  sheet(q, 'Tests', ['ID', 'Type', 'Priority', 'Title', 'Preconditions', 'Steps', 'Expected result', 'Stories', 'Requirements', 'Gate', 'Status', 'Executed by', 'Date', 'Notes'],
    T.map(t => [t[0], t[1], t[2], t[3], t[4], t[5], t[6], (storyByTest.get(t[0]) || []).join(', '), testReqs(t).join(', '), testGate(t), '', '', '', '']),
    [14, 10, 8, 36, 34, 50, 56, 20, 26, 8, 10, 12, 10, 20]);
  sheet(q, 'Release Blockers', ['ID', 'Blocker', 'Label', 'Tests', 'Gate(s)'], core.releaseBlockers.map(r => { const tr = trace.find(x => x.id === r[0]); return [...r, tr.tests, tr.gates]; }), [8, 60, 26, 40, 12], { labelCol: 2 });
  sheet(q, 'AI Eval', ['ID', 'Priority', 'Title', 'Preconditions', 'Steps', 'Expected / threshold', 'Requirements', 'Gate'],
    T.filter(t => t[1] === 'AI-eval').map(t => [t[0], t[2], t[3], t[4], t[5], t[6], testReqs(t).join(', '), testGate(t)]), [16, 8, 34, 34, 50, 56, 24, 8]);
  sheet(q, 'Strategy', ['Level', 'Scope', 'When', 'Tooling'], X.qaStrategy, [14, 70, 30, 34]);
  sheet(q, 'Environments', ['Environment', 'Purpose'], X.environments, [14, 90]);
  sheet(q, 'Definition of Done', ['#', 'Item', 'Label'], [...X.dodV11.map((d, i) => [i + 1, d, L.C]), ...X.dodAdd.map((d, i) => [X.dodV11.length + i + 1, d, L.R])], [5, 90, 28], { labelCol: 2 });
  await q.xlsx.writeFile(path.join(OUT, 'RuyaShield_QA_Test_Plan.xlsx'));

  // Traceability
  const t = new ExcelJS.Workbook();
  readme(t, 'RuyaShield Requirements Traceability', ['Matrix: Requirement → Epic → Story → API/Data → Test case → Acceptance gate.',
    'Derivation: stories list the requirements they implement; tests are linked through the stories\' QA lists and the tests\' own requirement references; gates come from the story phase or a gate set on the test.',
    `${trace.length} requirements traced (FR, SEC, RB, NFR). ${gapsReq.length} requirements and ${gapsStory.length} stories have no test yet (see Coverage gaps).`]);
  sheet(t, 'Matrix', ['Requirement', 'Kind', 'Title', 'Priority', 'Label', 'Epic(s)', 'Stories', 'API', 'Data', 'Test cases', 'Acceptance gate', '# stories', '# tests'],
    trace.map(r => [r.id, r.kind, r.title, r.priority, r.label, r.epics, r.stories, r.api, r.data, r.tests, r.gates, r.storyCount, r.testCount]),
    [11, 14, 40, 8, 26, 12, 30, 40, 40, 40, 12, 8, 8], { labelCol: 4 });
  sheet(t, 'Story → Test', ['Story', 'Epic', 'Phase', 'Requirements', 'Tests', 'Gate'], stories.map(s => [s.id, s.epic, s.phase, s.reqs.join(', '), (s.qa || []).join(', '), gateByPhase.get(s.phase) || '—']), [14, 8, 7, 40, 40, 8]);
  sheet(t, 'Test → Requirement', ['Test', 'Title', 'Stories', 'Requirements', 'Gate'], T.map(x => [x[0], x[3], (storyByTest.get(x[0]) || []).join(', '), testReqs(x).join(', '), testGate(x)]), [14, 40, 24, 40, 8]);
  sheet(t, 'Coverage gaps', ['Item', 'Kind', 'Detail', 'Action'], [
    ...gapsReq.map(r => [r.id, r.kind, r.title, 'Write a test case before the relevant gate']),
    ...gapsStory.map(s => [s.id, 'Story', `${s.title} (${s.phase}/${s.priority})`, 'Write tests during refinement']),
  ], [12, 14, 60, 40]);
  await t.xlsx.writeFile(path.join(OUT, 'RuyaShield_Requirements_Traceability.xlsx'));
}

// ================= Blueprint MD =================
function mdTable(h, rows) {
  const esc = v => String(Array.isArray(v) ? v.join('<br>') : v ?? '').replace(/\|/g, '\\|').replace(/\n/g, '<br>');
  return `| ${h.join(' | ')} |\n|${h.map(() => '---').join('|')}|\n${rows.map(r => `| ${r.map(esc).join(' | ')} |`).join('\n')}\n`;
}
const mmd = f => '```mermaid\n' + fs.readFileSync(path.join(DIAG, f), 'utf8').trim() + '\n```\n';
function blueprint() {
  const s = [];
  s.push(`# RuyaShield Technical Blueprint\n\nVersion ${meta.version} · ${meta.date} · companion to RuyaShield_PRD_v2.0_Implementation_Ready.docx (§6, §8–§13).\n\n> AI-assisted draft. Proposed design only: no application code exists yet. Every API is a proposed contract. The WebMonitor section is a provisional adapter (DEP-WM-01). Numbers marked "assumption" are provisional.\n`);
  s.push('## Contents\n\n1. Principles and constraints\n2. System context and containers\n3. Trust boundaries\n4. Modules\n5. Architecture decision records\n6. State machines\n7. AI gateway\n8. FixProof\n9. Sandbox and egress guard\n10. Data model\n11. API conventions and endpoints\n12. Events\n13. WebMonitor adapter (provisional)\n14. Open technical decisions\n');
  s.push('## 1. Principles and constraints\n\n' + X.vision.principles.map(p => `- ${p}`).join('\n') +
    '\n- Testing only of explicitly authorized, verified (or attested) assets within an approved, versioned scope.\n- Check classes: **P** passive, **A1** active-safe, **A2** approval-required (flag off in MVP), **X** prohibited (never executable).\n- RuyaShield opens pull requests only. It never merges or deploys.\n- Failed, inconclusive, error and not_run results are never shown as passed.\n\nStack (from v1.1): Next.js 16+, React 19, TypeScript, Tailwind; PostgreSQL (ORM per D-02) with RLS; OIDC identity provider (D-04); AWS: SQS + outbox, private S3 with SSE-KMS, Secrets Manager, KMS; isolated workers.\n');
  s.push('## 2. System context and containers\n\n' + mmd('context.mmd') + '\n' + mmd('containers.mmd'));
  s.push('## 3. Trust boundaries\n\n' + mmd('trust.mmd') + '\n' + mdTable(['ID', 'Boundary', 'Data crossing', 'Controls'], X.trustBoundaries));
  s.push('## 4. Modules\n\n' + mdTable(['Module', 'Responsibility', 'Runs in', 'Epics'], X.modules) + '\nRule: modules talk only through their public service interfaces and domain events, enforced by lint rules on import paths. Every database access sets `app.org_id` with `SET LOCAL` inside the transaction so that RLS applies.\n');
  s.push('## 5. Architecture decision records\n\n' + X.adrs.map(a => `### ${a[0]} ${a[1]}\n\n- **Decision:** ${a[2]}\n- **Rationale:** ${a[3]}\n- **Consequences:** ${a[4]}\n- **Status:** ${a[5]} · *${a[6]}*\n`).join('\n'));
  s.push('## 6. State machines\n\nAction types: ' + X.actionTypes.map(a => `**${a[0]}** ${a[1]} (${a[2]})`).join('; ') + '. A transition that is not listed returns `422 transition_not_allowed`.\n');
  const sm = [['Assessment', 'assessment_sm.mmd', 'assessment'], ['Finding', 'finding_sm.mmd', 'finding'], ['Remediation', 'remediation_sm.mmd', 'remediation'], ['Approval', 'approval_sm.mmd', 'approval'], ['Verification run', 'verification_sm.mmd', 'verification']];
  for (const [n, f, k] of sm) s.push(`### ${n}\n\n` + mmd(f) + '\n' + mdTable(['From', 'To', 'Trigger / guard', 'Actor', 'Type'], X.transitions[k]));
  s.push('### Asset verification\n\n' + mdTable(['From', 'To', 'Trigger / guard', 'Actor', 'Type'], X.transitions.asset));
  s.push('### Assessment launch pre-checks\n\n' + mmd('assessment_flow.mmd') + '\n### Remediation to pull request\n\n' + mmd('remediation_seq.mmd'));
  s.push('## 7. AI gateway\n\n' + mdTable(['ID', 'Use case', 'Status', 'Inputs', 'Output', 'Fallback / enforcement', 'Story'], X.aiUseCases) + '\n' + mdTable(['Claim type', 'Definition', 'Validation'], X.aiClaimTypes) + '\n' + mdTable(['Control', 'Specification', 'Label'], X.aiControls));
  s.push('## 8. FixProof\n\n' + mmd('fixproof_seq.mmd') + '\n' + mdTable(['Section', 'Fields'], X.fixproofContents) + '\n' + mdTable(['Run results', 'FixProof status', 'Finding outcome', 'Note'], X.fixproofStatus) + '\n' + X.fixproofRules.map(r => `- ${r}`).join('\n') + '\n');
  s.push('## 9. Sandbox and egress guard\n\n' + mdTable(['Aspect', 'Specification', 'Label'], X.sandbox) + '\n**Egress guard rules**\n\n' + X.egress.map(r => `- ${r}`).join('\n') + '\n');
  s.push('## 10. Data model\n\n' + mmd('erd.mmd') + '\n' + mdTable(['Table', 'Purpose', 'Key columns', 'Tenancy', 'Retention (assumption)'], X.tables) + '\n### Retention\n\n' + mdTable(['Data', 'Retention', 'Reason', 'Label'], X.retention) + '\n### Audit event catalogue\n\n' + mdTable(['Event types', 'Epic'], X.auditCatalogue));
  s.push('## 11. API conventions and endpoints\n\n' + X.apiConventions.map(r => `- ${r}`).join('\n') + '\n\n' + mdTable(['Method', 'Path', 'Purpose', 'Roles', 'Story'], X.api) + '\n### Examples\n\n' + X.jsonExamples.map(([t, c]) => `**${t}**\n\n\`\`\`jsonc\n${c}\n\`\`\`\n`).join('\n'));
  s.push('## 12. Events\n\n' + mdTable(['Event', 'Producer', 'Consumers', 'Key payload'], X.events) + '\n**Envelope**\n\n```json\n' + X.eventEnvelope + '\n```\n\nDelivery is at-least-once through the transactional outbox. Consumers dedupe on `idempotency_key`, and the dedupe record is kept for 7 days (assumption).\n');
  s.push('## 13. WebMonitor adapter (provisional)\n\n' + mdTable(['Aspect', 'Specification', 'Label'], X.wmAdapter) + '\n```ts\n' + X.wmInterface + '\n```\n');
  s.push('## 14. Open technical decisions\n\n' + mdTable(['ID', 'Decision', 'Recommendation', 'Label', 'Owner', 'Needed by', 'Impact'], decSorted));
  return s.join('\n');
}

(async () => {
  fs.writeFileSync(path.join(OUT, 'RuyaShield_PRD_v2.0_Implementation_Ready.docx'), await D.Packer.toBuffer(doc));
  await buildXlsx();
  fs.writeFileSync(path.join(OUT, 'RuyaShield_Technical_Blueprint.md'), blueprint());
  console.log(JSON.stringify({ stories: stories.length, tests: T.length, reqs: trace.length, gapsReq: gapsReq.map(r => r.id), gapsStory: gapsStory.map(s => s.id) }));
})();
