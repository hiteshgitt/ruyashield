import Link from "next/link";

export type Segment = { label: string; count: number; tone: string; href?: string };

/**
 * Proportional bar built from real counts, followed by a legend that states every count in words.
 * The bar is decorative (aria-hidden); the legend carries the information. With no counts it shows `empty` instead of a bar.
 */
export function Meter({ segments, empty }: { segments: Segment[]; empty: string }) {
  const total = segments.reduce((n, s) => n + s.count, 0);
  if (total === 0) return <p className="muted small">{empty}</p>;
  return (
    <>
      <div className="meter" aria-hidden="true">
        {segments.filter((s) => s.count > 0).map((s) => <span key={s.label} className={`seg ${s.tone}`} style={{ flexGrow: s.count }} />)}
      </div>
      <ul className="legend meter-legend">
        {segments.map((s) => (
          <li key={s.label} className={s.tone}>
            <span className="n">{s.count}</span> {s.href && s.count > 0 ? <Link href={s.href}>{s.label}</Link> : s.label}
          </li>
        ))}
      </ul>
    </>
  );
}
