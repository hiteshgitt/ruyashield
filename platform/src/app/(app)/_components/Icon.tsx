// Stroke icons for the app shell. Decorative only: every icon sits next to a text label or an aria-label.
const PATHS = {
  overview: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  assets: "M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z",
  assessments: "M3 12h4l3-7 4 14 3-7h4",
  findings: "M12 3.5l9 16H3zM12 10v4M12 17v.01",
  approvals: "M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18zM8 12.5l2.7 2.7L16 10",
  reports: "M6 3h8l4 4v14H6zM14 3v4h4M9 12h6M9 16h6",
  members: "M9 11a3.5 3.5 0 1 0 0-7a3.5 3.5 0 0 0 0 7zM2.5 20c.8-3.5 3.4-5.5 6.5-5.5s5.7 2 6.5 5.5M16 4.5a3.5 3.5 0 0 1 0 6.5M18 14.8c1.8.7 3 2.6 3.5 5.2",
  repos: "M6 3v12M6 21a2.5 2.5 0 1 0 0-5a2.5 2.5 0 0 0 0 5zM18 9a2.5 2.5 0 1 0 0-5a2.5 2.5 0 0 0 0 5zM18 9c0 5-6 4-12 7",
  safety: "M12 3v8M6.3 6.8a8 8 0 1 0 11.4 0",
  tokens: "M15 3a6 6 0 1 1-5.6 8.2L3 17.6V21h3.4v-2.4h2.4v-2.4h2.4l1.2-1.2A6 6 0 0 1 15 3zM16.5 7.5v.01",
  org: "M4 21V5l8-2v18M12 8h8v13M8 8v.01M8 12v.01M8 16v.01M16 12v.01M16 16v.01M2 21h20",
  audit: "M9 3.5h6v3H9zM7 5H5v16h14V5h-2M8.5 12h7M8.5 16h5",
  bell: "M6 16v-5a6 6 0 0 1 12 0v5l1.5 2h-15zM10 20.5a2 2 0 0 0 4 0",
  menu: "M4 7h16M4 12h16M4 17h16",
  chevron: "M7 10l5 5 5-5",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10",
  plus: "M12 5v14M5 12h14",
  shield: "M12 3l8 3v6c0 4.5-3.4 8.1-8 9-4.6-.9-8-4.5-8-9V6zM8.8 12.2l2.2 2.2 4.2-4.4",
  check: "M5 12.5l4.5 4.5L19 7.5",
  clock: "M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18zM12 7v5l3.5 2",
  radar: "M12 3a9 9 0 1 0 9 9M12 7a5 5 0 1 0 5 5M12 12l6.5-6.5M12 12v.01",
  monitor: "M3 4.5h18v11.5H3zM8 20h8M12 16v4M6 11.5h2.5l1.5-3 2.5 5 1.5-2h3.5",
  target: "M12 3a9 9 0 1 0 0 18a9 9 0 0 0 0-18zM12 7.5a4.5 4.5 0 1 0 0 9a4.5 4.5 0 0 0 0-9zM12 11.5v1",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg className={className ? `icon ${className}` : "icon"} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <path d={PATHS[name]} />
    </svg>
  );
}
