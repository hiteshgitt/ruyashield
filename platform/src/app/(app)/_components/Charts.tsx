import Link from "next/link";
import type { ReactNode } from "react";
import type { Severity } from "@/server/db/schema";
import type { AreaRow, AssetTile, Score, TrendWeek } from "@/server/reports/insights";
import { TIER_LABEL, type AreaTier } from "@/server/reports/areas";
import { areaState } from "@/server/reports/nextStep";
import { Icon, type IconName } from "./Icon";

// Server-rendered SVG charts for the dashboard. No chart library and no client JS.
// Every chart is aria-hidden; the numbers it shows are always present as text next to it (legend, caption or link).

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

/** Icon stat card: the big number links to the list it counts. */
export function StatCard({ icon, label, value, href, sub, tone }: { icon: IconName; label: string; value: number | string; href?: string; sub?: ReactNode; tone?: "ok" | "warn" | "bad" | "violet" }) {
  return (
    <div className={`stat tone-${tone ?? "violet"}`}>
      <span className="stat-icon"><Icon name={icon} /></span>
      <div className="stat-body">
        <h3 className="stat-label">{label}</h3>
        <p className="stat-value">{href ? <Link href={href}>{value}</Link> : value}</p>
        {sub && <p className="stat-sub">{sub}</p>}
      </div>
    </div>
  );
}

/** Semicircle 0–100 gauge. With no score it draws an empty track and says why. */
export function ScoreGauge({ score }: { score: Score | null }) {
  const tone = !score ? "none" : score.value >= 75 ? "ok" : score.value >= 50 ? "warn" : "bad";
  const arc = "M 20 100 A 80 80 0 0 1 180 100";
  return (
    <div className={`gauge tone-${tone}`}>
      <svg viewBox="0 0 200 112" aria-hidden="true" focusable="false">
        <defs>
          <linearGradient id="gauge-track" x1="0" x2="1"><stop offset="0" stopColor="#f87171" /><stop offset=".5" stopColor="#facc15" /><stop offset="1" stopColor="#6ee7a0" /></linearGradient>
        </defs>
        <path d={arc} className="gauge-track" pathLength={100} />
        {score && <path d={arc} className="gauge-ticks" pathLength={100} />}
        {score && <path d={arc} className="gauge-fill" pathLength={100} style={{ strokeDasharray: `${score.value} 100` }} />}
      </svg>
      <div className="gauge-readout">
        {score ? <><span className="gauge-value">{score.value}</span><span className="gauge-grade">Grade {score.grade}</span></>
          : <><span className="gauge-value muted">—</span><span className="gauge-grade">No score yet</span></>}
      </div>
    </div>
  );
}

/** Severity donut with the open total in the centre and a linked legend carrying every count. */
export function SeverityDonut({ open, total }: { open: Record<Severity, number>; total: number }) {
  const r = 52, c = 2 * Math.PI * r;
  const present = SEVERITIES.filter((s) => open[s] > 0);
  const arcs = present.map((s, i) => {
    const before = present.slice(0, i).reduce((t, p) => t + open[p], 0);
    const len = (open[s] / total) * c;
    return { s, dash: `${Math.max(0, len - (present.length > 1 ? 2 : 0))} ${c}`, off: -(before / total) * c };
  });
  return (
    <div className="donut-wrap">
      <div className="donut">
        <svg viewBox="0 0 140 140" aria-hidden="true" focusable="false">
          <circle cx="70" cy="70" r={r} className="donut-track" />
          {arcs.map((a) => <circle key={a.s} cx="70" cy="70" r={r} className={`donut-seg sev-${a.s}`} style={{ strokeDasharray: a.dash, strokeDashoffset: a.off }} />)}
        </svg>
        <div className="donut-center"><span className="donut-total">{total}</span><span className="donut-caption">open</span></div>
      </div>
      <ul className="legend legend-col">
        {SEVERITIES.map((s) => (
          <li key={s} className={`sev-${s}`}>
            <Link href={`/findings?severity=${s}`}><span className="legend-name">{s}</span> <strong>{open[s]}</strong></Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Weekly grouped bars: findings first seen vs findings resolved with a verified re-test. */
export function TrendChart({ weeks }: { weeks: TrendWeek[] }) {
  const W = 640, H = 220, L = 34, B = 26, T = 12, R = 8;
  const max = Math.max(4, ...weeks.flatMap((w) => [w.opened, w.resolved]));
  const step = Math.ceil(max / 4);
  const top = step * 4;
  const y = (v: number) => T + (H - T - B) * (1 - v / top);
  const colW = (W - L - R) / weeks.length;
  const bw = Math.min(14, colW / 3);
  const label = (d: Date) => d.toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
  return (
    <svg className="trend" viewBox={`0 0 ${W} ${H}`} aria-hidden="true" focusable="false">
      {[0, 1, 2, 3, 4].map((i) => (
        <g key={i}>
          <line x1={L} x2={W - R} y1={y(i * step)} y2={y(i * step)} className="trend-grid" />
          <text x={L - 8} y={y(i * step) + 4} className="trend-axis" textAnchor="end">{i * step}</text>
        </g>
      ))}
      {weeks.map((w, i) => {
        const cx = L + colW * i + colW / 2;
        return (
          <g key={i} className="trend-col" style={{ ["--i" as string]: i }}>
            <title>{`Week of ${label(w.weekStart)}: ${w.opened} found, ${w.resolved} resolved (verified)`}</title>
            <rect x={L + colW * i} y={T} width={colW} height={H - T - B} className="trend-hit" />
            <rect x={cx - bw - 1} y={y(w.opened)} width={bw} height={Math.max(0, H - B - y(w.opened))} rx="3" className="trend-bar opened" />
            <rect x={cx + 1} y={y(w.resolved)} width={bw} height={Math.max(0, H - B - y(w.resolved))} rx="3" className="trend-bar resolved" />
            {(i % 2 === weeks.length % 2 || weeks.length <= 6) && <text x={cx} y={H - 8} className="trend-axis" textAnchor="middle">{label(w.weekStart)}</text>}
          </g>
        );
      })}
    </svg>
  );
}

/** Asset block map: one tile per asset, coloured by its worst open severity. Grey = not assessed or not verified. */
export function AssetMap({ tiles }: { tiles: AssetTile[] }) {
  return (
    <ul className="blockmap">
      {tiles.map((t) => {
        const state = t.status !== "verified" ? "unverified" : !t.lastAssessedAt ? "unassessed" : t.worst ? `sev-${t.worst}` : "clean";
        const what = state === "unverified" ? `ownership ${t.status}` : state === "unassessed" ? "not assessed yet"
          : t.openTotal === 0 ? "no open findings from the checks that ran" : `${t.openTotal} open, worst ${t.worst}`;
        return (
          <li key={t.id}>
            <Link href={`/assets/${t.id}`} className={`block ${state}`} title={`${t.host}: ${what}`}>
              <span className="block-host">{t.host.startsWith("repo:") ? `repo · ${t.host.slice(5)}` : t.host}</span>
              <span className="block-meta">{state.startsWith("sev-") ? `${t.openTotal} open` : what}</span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

const TIERS: readonly AreaTier[] = ["essential", "important", "hygiene"];
const TIER_HINT: Record<AreaTier, string> = {
  essential: "Attackers exploit these directly. Fix first.",
  important: "These weaken your defences.",
  hygiene: "These reduce risk and limit the damage.",
};

/** Security areas grouped by importance: each card says why it matters, its state, and a severity bar. */
export function AreaBoard({ areas }: { areas: readonly AreaRow[] }) {
  return (
    <div className="area-board">
      {TIERS.map((t) => {
        const rows = areas.filter((a) => a.tier === t);
        if (!rows.length) return null;
        return (
          <section key={t} className={`tier tier-${t}`} aria-labelledby={`tier-${t}`}>
            <h4 id={`tier-${t}`}><span className="tier-name">{TIER_LABEL[t]}</span> <span className="muted small">{TIER_HINT[t]}</span></h4>
            <ul className="area-cards">
              {rows.map((a) => {
                const st = areaState(a);
                const body = (
                  <>
                    <span className="area-head"><span className="area-dot" aria-hidden="true" /><span className="area-name">{a.label}</span></span>
                    <span className="area-why">{a.why}</span>
                    {a.open > 0 && (
                      <span className="area-bar" aria-hidden="true">
                        {SEVERITIES.filter((s) => a.bySeverity[s] > 0).map((s) => <span key={s} className={`sev-${s}`} style={{ flexGrow: a.bySeverity[s] }} />)}
                      </span>
                    )}
                    <span className="area-state">{st.text}</span>
                    {a.open > 0 && <span className="area-counts">{SEVERITIES.filter((s) => a.bySeverity[s] > 0).map((s) => `${a.bySeverity[s]} ${s}`).join(" · ")}</span>}
                  </>
                );
                return (
                  <li key={a.key} className={`area-card ${st.cls}`}>
                    {a.covered ? <Link href={`/findings?area=${a.key}&status=open`}>{body}</Link> : <div>{body}</div>}
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

const SEV_HINT: Record<Severity, string> = {
  critical: "Fix now",
  high: "Fix this sprint",
  medium: "Plan a fix",
  low: "When convenient",
  info: "For awareness",
};

/**
 * One clickable card per severity, with the count as text and a proportional bar (aria-hidden).
 * Zero is shown as "0", never as "clean": it only means no check that ran reported one.
 */
export function SeverityCards({ counts, hrefFor, active }: { counts: Record<Severity, number>; hrefFor: (s: Severity | null) => string; active?: string }) {
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  return (
    <ul className="sev-cards" aria-label="Findings by severity">
      {SEVERITIES.map((s) => {
        const on = active === s;
        return (
          <li key={s} className={`sev-card sev-${s}${on ? " active" : ""}${counts[s] === 0 ? " zero" : ""}`}>
            <Link href={hrefFor(on ? null : s)} aria-current={on ? "true" : undefined}>
              <span className="sev-card-name">{s}</span>
              <span className="sev-card-n">{counts[s]}</span>
              <span className="sev-card-bar" aria-hidden="true"><span style={{ width: `${total ? Math.round((counts[s] / total) * 100) : 0}%` }} /></span>
              <span className="sev-card-hint">{on ? "Showing only these · clear" : SEV_HINT[s]}</span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
