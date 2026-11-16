# RuyaShield design system

How the public site and the signed-in app look, and the rules that keep them honest. Everything here describes
code that exists in `platform/src/app/`; when the two disagree, the code wins and this file should be fixed.

## 1. Two themes, one brand

| | Public site | Signed-in app |
|---|---|---|
| Scope class | `.site` (`data-site="marketing"` on the wrapper) | `.app` |
| Styles | `(site)/site.css`, `(site)/above-1920.css` | `(app)/app.css` |
| Layout model | Fluid, 1920 reference design, no max-width containers, proportional root scaling from 1200px (fluid rules apply to public pages only) | Normal responsive layout: sidebar from 64rem, `main` capped at 84rem |
| Motion | GSAP (`SiteMotion`, `Reveal`) | CSS keyframes only |
| Colour mode | Dark only | Dark only |

Both are scoped so neither can leak into the other. `globals.css` only imports Tailwind and sets a body font for
pages outside both themes (Next's built-in 404). The few element defaults the themes still relied on are at the
top of `app.css` and `site.css`, under `:where()` so every theme rule still overrides them.

## 2. Tokens

### Shared — `tokens.css` (applies to `.site, .app`)

Only values that are identical in both themes.

| Token | Value | Use |
|---|---|---|
| `--text` | `#ecebf3` | Primary text |
| `--line` | `rgba(236,235,243,.08)` | Hairline dividers, card borders |
| `--line-2` | `rgba(236,235,243,.14)` | Stronger borders, inputs |
| `--violet` | `#8b5cf6` | Brand accent (buttons use `--btn-*`) |
| `--violet-2` | `#a78bfa` | Accent, links |
| `--violet-3` | `#c4b5fd` | Focus ring, code text, eyebrows |
| `--amber` | `#f5b14c` | Secondary brand accent, "illustrative" tags |
| `--btn-top` / `--btn-bottom` | `#8250f2` / `#6d28d9` | Primary-button and avatar gradient; white text stays ≥ 4.5:1 across it (4.8:1 top, 7.1:1 bottom). No hover brighten. |
| `--ease` | `cubic-bezier(.2,.7,.2,1)` | All transitions and keyframes |

### App only — `app.css`

| Group | Tokens |
|---|---|
| Surfaces | `--bg #0b0a10`, `--bg-2 #0f0e15`, `--surface #14131b`, `--surface-2 #1a1823`, `--surface-3 #22202d`, `--code-bg #1c1a26` |
| Text | `--text-2 #b8b5c8`, `--muted #9894ad` (6.3:1 on `--surface`) |
| Status | `--ok` / `--ok-bg` / `--ok-line`, `--warn` / `-bg` / `-line`, `--bad` / `-bg` / `-line` |
| Shape | `--radius-sm .5rem`, `--radius .75rem`, `--radius-lg 1rem`, `--shadow` |
| Accent | `--accent` (= `--violet-2`), `--accent-text #fff`, `--violet-glow` |

Chart tones (`.seg`, `.legend li`): `ok`, `warn`, `warn-soft`, `bad`, `none`, and severity tones
`sev-critical`, `sev-high`, `sev-medium`, `sev-low`, `sev-info`.

### Site only — `site.css`

| Group | Tokens |
|---|---|
| Surfaces | `--bg #07060c`, `--bg-2`, `--surface`, `--surface-2`, `--surface-3` (deeper than the app on purpose) |
| Text | `--text-2 #b0adc2`, `--text-3 #8f8ba5` |
| Accents | `--green`, `--red`, `--blue`, `--violet-glow` |
| Fluid sizes | `--gutter`, `--fs-hero`, `--fs-display`, `--fs-title`, `--section-y`, `--panel-pad`, `--gap` — all `clamp()` against the 1920 design |
| Shape | `--radius .875rem`, `--radius-lg 1.25rem` |

Rule: new values go in the theme block, never inline in markup. Only move a token to `tokens.css` when it is
genuinely the same in both themes.

## 3. Typography

Fonts are loaded with `next/font/google` in each route-group layout and exposed as CSS variables:

| Variable | Font | Use |
|---|---|---|
| `--font-display` | Funnel Display | Headings, brand, KPI values |
| `--font-sans` | Funnel Sans | Body text, controls |
| `--font-mono` | Geist Mono | Code, hashes, hosts, uppercase labels (nav groups, eyebrows, table headers) |

App scale: body `.9375rem`; `h1 1.75rem`, `h2 1.125rem`, `h3 1rem`; `.small .8125rem`. Nothing below `.6875rem`,
and that size only for uppercase mono labels.

## 4. Layout and breakpoints (app)

| Breakpoint | What changes |
|---|---|
| `< 40rem` (640) | Brand and menu label hidden in the top bar; org name truncated shorter |
| `< 48rem` (768) | Org switcher shrinks so its name truncates and the top bar stays one row |
| `≥ 48rem` (768) | User name and MFA state shown; two-column forms and decision panels |
| `≥ 64rem` (1024) | Sidebar appears; `.split` becomes main + 21rem side column; two-column switch grid and audit header |
| `≥ 75rem` (1200) | Finding detail becomes main column + 20rem side column |

The app frame is a two-row grid (`auto 1fr`): the top bar keeps its own height however short the page is.

Layout helpers: `.stack` (vertical rhythm), `.row` (wrapping horizontal group), `.grid2`, `.split` /
`.split-main` / `.split-side`, `.detail` / `.detail-main` / `.detail-side`, `.table-wrap` (tables scroll inside
the wrapper, never the page; render it with `TableWrap`).

## 5. Components

### App — `(app)/_components/`

| Component | Purpose |
|---|---|
| `PageHeader` (`Page.tsx`) | Screen `h1` with an optional lead (`muted small`) saying what the numbers on the page mean |
| `Loading` (`Page.tsx`) | Suspense fallback; `what="evidence"` renders "Loading evidence…" |
| `Empty` (`Page.tsx`) | Empty list/table. Say what is missing and, where it matters, what the absence does **not** prove |
| `MetaChips` (`Page.tsx`) | Row of summary chips; each child is an `<li>`; `label` names the list for screen readers |
| `SectionHead` (`Page.tsx`) | Heading plus trailing context. `variant="section"` heads a block of cards; `variant="setting"` pairs one setting with its state badge |
| `StatusBadge` | Maps a backend status to `ok` / `warn` / `bad` / neutral and prints the status as words |
| `Meter` | Proportional bar from real counts plus a legend stating every count; the bar is `aria-hidden` |
| `Coverage` | "N of M checks ok" with a thin bar; anything short of full coverage gets the warning tone |
| `ActionForm` | Server-action form with pending state, result notice and `primary` / `secondary` / `danger` submit |
| `NavList` | Grouped navigation with `aria-current`; used by sidebar and mobile menu |
| `AppChrome`, `ShellBehavior` | Sidebar, top bar, org/user menus and their client behaviour |
| `Icon` | Inline SVG icon set (`IconName`) |
| `TableWrap` | `.table-wrap` wrapper for every app table, and (`as="pre"`) for change diffs. If the content overflows, it becomes a focusable `role=region` labelled with the nearest heading plus "(scrolls sideways)", or "(scrollable)" when it also scrolls down; content that fits gets no extra tab stop. Set the label with `label` if needed. |

Where a screen's heading has extra content inside it (finding title with badges, assessment title with a link,
mono asset title), it keeps hand-written markup rather than stretching `PageHeader`.

### Site — `(site)/_components/`

| Component | Purpose |
|---|---|
| `SiteHeader`, `SiteFooter`, `Logo` | Public chrome |
| `Reveal` | Marks a block for scroll reveal; markup is static and visible without JS |
| `SiteMotion` | All public-site GSAP motion (reveals, staggers, decode labels, spotlight cards) |
| `Workflow` | Six-stage workflow as an accessible tablist (arrow keys, Home, End) |
| `cn` | Joins class names so callers can extend a component's classes |

## 6. Core classes (app)

| Class | Meaning |
|---|---|
| `.card`, `.panel` | Raised surface; a card inside a card drops to `--bg-2` with no shadow |
| `.badge` (`.ok` / `.warn` / `.bad`) | Status pill with a dot **and** text |
| `.notice` (`.ok` / `.warn` / `.bad`) | Inline message block; `role` set when it announces a result |
| `.muted`, `.small`, `.mono`, `.nowrap`, `.sr-only` | Text utilities |
| `.empty` | Empty state (use `Empty`) |
| `.meta-chips` | Summary chips (use `MetaChips`) |
| `.kpis` / `.kpi` | Dashboard figures from recorded data |
| `.danger-zone`, `.danger-eyebrow`, `.consequences` | Destructive settings: list the consequences before the control |
| `.zealot*` | The AI analysis panel (see rule 7.3) |
| `.source-tag`, `.class-tag`, `.cite` | Provenance and check-class labels |
| `button` (default primary), `button.secondary`, `button.danger`, `a.button` | Controls |

Site-only: `.eyebrow`, `.display`, `.illus` ("Illustrative example — not live data"; inside a frame bar it wraps
rather than being cut off).

## 7. Rules

These are product rules, not style preferences. A change that breaks one is a bug.

1. **Status is always text.** Colour and dots support the label; they never replace it. Every badge, legend
   entry and coverage bar states its value in words. Bars and meters are `aria-hidden` because the text carries
   the information.
2. **Failed, incomplete and inconclusive never look passed.** `inconclusive`, `partially_verified`,
   `completed_with_errors`, timeouts and partial coverage take the warning or bad tone, never `ok`. Counts come from
   recorded assessments and verification re-tests only.
3. **AI output is visually separate.** The Zealot panel uses a dashed border and hatched background, is titled
   "Zealot · AI analysis", shows its limitations, and is never styled like verified evidence. AI text never
   marks a finding fixed; only a verification re-test does.
4. **No fake data.** Public-site product visuals carry the `.illus` tag and use `example.com`. No invented
   customers, logos, testimonials, certifications or integrations. Empty states say what is missing instead of
   showing placeholders.
5. **Dangerous actions are explicit.** Kill switches, legal hold and deletion sit in `setting-head` / `danger-zone`
   blocks with their current state as a badge, the consequences listed, a required reason, and (for deletion) a
   typed confirmation. Nothing destructive is a one-click default.
6. **Accessibility (WCAG 2.2 AA).** Text contrast ≥ 4.5:1 (`--muted` is 6.3:1 on `--surface`); visible
   `:focus-visible` ring in `--violet-3`; a skip link; `aria-current` in navigation; `aria-labelledby` on
   settings sections; tables and diffs inside `TableWrap`, so anything that scrolls is keyboard-reachable; interactive targets
   at least 24px (2.5.8).
7. **Motion is optional.** All motion sits behind `prefers-reduced-motion: no-preference`. App motion is CSS only,
   so streamed (Suspense) content animates too and nothing is ever hidden when animation can't run. The site's
   GSAP never hides server markup except the hero, which a fallback timer reveals.
8. **Sizing.** App: rem throughout. Site: rem or the fluid tokens only, because `above-1920.css` scales the root
   font size; px only for hairlines.

## 8. Changing the UI

- Reuse a component or class from sections 5–6 before writing new markup.
- Put new tokens in the right block (section 2); don't inline colours.
- Before handing over, run the visual regression (19 screens × 390/1024/1440 against the stored baseline),
  `npx tsc --noEmit` and eslint, and say which differences are intended.
