# UI / UX design

## Palette (dark default; light theme toggle)
| Token | Dark | Light | Used for |
|---|---|---|---|
| Primary | #3D7BFF | #2563EB | Main actions, active nav, focus rings, confidence bars |
| Secondary | #14B8A6 | #0D9488 | ML signals, "ML" evidence chips, secondary CTA |
| Accent | #A78BFA | #7C3AED | AI/LLM elements, citations, triage model |
| Background | #0B1220 | #F4F6FB | App canvas |
| Surface | #111A2E | #FFFFFF | Cards, sidebar, drawer |
| Surface-2/3 | #16213A / #1C2946 | #F1F4FA / #E8EDF6 | Table headers, chips, bar tracks |
| Border | #23314F | #E3E8F2 | Card and table borders |
| Text / Text-2 / Muted | #E6EBF5 / #9AA8C1 / #6B7A96 | #0F172A / #475569 / #64748B | Body, secondary, labels |
| Success | #22C55E | same | Accept, fixed, on-prem badge |
| Warning | #F59E0B | same | Log evidence, governance notes |
| Error | #EF4444 | same | Reject, errors, blocked prompts |
| Severity | critical #F43F5E · high #F97316 · medium #F59E0B · low #38BDF8 | | Chips, donut, heatmap, gutter |

## Layout
Sidebar (248 px; 76 px icon rail under 1100 px; off-canvas under 760 px) + sticky top bar (repo switcher, Run analysis, theme).
Dashboard: 6 KPI cards → priority queue + severity donut → categories / trend / hotspots → file-risk heatmap.

## Components
KPI cards · tables with severity/status chips · evidence chips (R/ML/L/AI/T) · confidence bars · SVG donut/bar/line/heatmap (no chart library) ·
finding drawer with code context, confidence breakdown and tabs · syntax-highlighted code viewer with gutter markers · chat with citation
buttons and expandable sources · drag-and-drop upload · step-progress modal · segmented controls · toasts · skeleton loaders · empty states.

## Typography & spacing
System UI stack (Inter / Segoe UI) at 14 px base; headings 24/18/15 px; monospace (JetBrains Mono / Consolas) for code and paths.
4-px rhythm, 16–20 px gaps, 14 px card radius.

## UX reasoning
- **Explainability first:** every finding answers "why should I trust this?" — fits the governance principle.
- **Priority over volume:** queue sorted by severity × confidence; heatmap shows where to look first.
- **Human in control:** accept / reject (reason required) / fix; no auto-merge; rejections remembered.
- **Dark default:** suits long code-review sessions; body text meets WCAG AA contrast.
- **Offline & CSP-safe:** no CDNs or web fonts, consistent with "no external transmission".
