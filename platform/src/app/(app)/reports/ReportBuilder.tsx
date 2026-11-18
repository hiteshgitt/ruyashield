"use client";
import { useActionState, useState } from "react";
import type { ActionState } from "../_lib/action";

type Section = { key: string; label: string; hint: string };
type Preset = { key: string; label: string; hint: string; sections: string[]; minSeverity: string; includeFixes: boolean };

/** Report type cards; "Custom" unlocks the section checkboxes, severity and fixes. The summary is always in. */
export function ReportBuilder({ action, sections, presets, groups, groupId, restricted }: {
  action: (prev: ActionState, f: FormData) => Promise<ActionState>;
  sections: Section[]; presets: Preset[]; groups: { id: string; name: string }[]; groupId: string; restricted: boolean;
}) {
  const [state, formAction, pending] = useActionState(action, null);
  const [preset, setPreset] = useState("client");
  const current = presets.find((p) => p.key === preset);
  const [picked, setPicked] = useState<string[]>(presets.find((p) => p.key === "technical")!.sections);
  const custom = preset === "custom";
  const active = custom ? picked : current!.sections;

  return (
    <form action={formAction} className="stack report-builder">
      <fieldset className="report-presets">
        <legend>Report type</legend>
        {[...presets, { key: "custom", label: "Custom", hint: "Pick the sections, severities and detail yourself." } as Preset].map((p) => (
          <label key={p.key} className={`report-preset${preset === p.key ? " on" : ""}`}>
            <input type="radio" name="preset" value={p.key} checked={preset === p.key} onChange={() => setPreset(p.key)} />
            <span className="report-preset-title">{p.label}</span>
            <span className="report-preset-hint">{p.hint}</span>
          </label>
        ))}
      </fieldset>

      <fieldset className="report-sections" disabled={!custom}>
        <legend>Sections {custom ? "" : <span className="muted small">(set by the report type)</span>}</legend>
        {sections.map((s) => (
          <label key={s.key} className="check-opt">
            <input type="checkbox" name="sections" value={s.key}
              checked={s.key === "summary" || active.includes(s.key)} disabled={s.key === "summary"}
              onChange={(e) => setPicked((x) => (e.target.checked ? [...x, s.key] : x.filter((k) => k !== s.key)))} />
            <span className="check-text"><span className="check-title">{s.label}</span><span className="muted small">{s.hint}</span></span>
          </label>
        ))}
      </fieldset>

      {custom && (
        <div className="report-row">
          <label>Findings to include
            <select name="minSeverity" defaultValue="info">
              <option value="critical">Critical only</option>
              <option value="high">High and above</option>
              <option value="medium">Medium and above</option>
              <option value="low">Low and above</option>
              <option value="info">All severities</option>
            </select>
          </label>
          <label className="check-opt inline"><input type="checkbox" name="includeFixes" defaultChecked /> <span>Include the fix for each finding</span></label>
        </div>
      )}

      <label>Title (optional)<input name="title" maxLength={120} placeholder="e.g. Monthly security report for Acme" /></label>
      <div className="report-row">
        <label>Format <select name="format" defaultValue="pdf"><option value="pdf">PDF</option><option value="csv">CSV (spreadsheet)</option></select></label>
        <label>Scope <select name="clientGroupId" defaultValue={groupId}>
          <option value="">{restricted ? "All my client groups" : "All assets"}</option>
          {groups.map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
        </select></label>
      </div>
      <p className="muted small">Every report lists failed and incomplete checks and its limitations, and records its SHA-256. Not a certification.</p>
      <div><button type="submit" disabled={pending}>{pending ? "Generating…" : "Generate report"}</button></div>
      {state?.error && <p className="notice bad" role="alert">{state.error}</p>}
      {state?.ok && <p className="notice ok" role="status">{state.ok}</p>}
    </form>
  );
}
