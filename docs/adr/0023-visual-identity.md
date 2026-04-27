---
status: "accepted"
date: 2026-04-27
decision-makers: Patrick Fenerty
---

# Visual Identity — Field Guide / Entry Cards

## Context and Problem Statement

The OCIDex name riffs on Pokédex, but the UI today is a generic dark-mode dev-tool: flat cards, Inter body text, hand-rolled SVG icons. The design tokens in `web/src/index.css` already lean Pokédex-red/blue (lines 7–86), but nothing in the chrome cashes that in. Before public launch (1.0.I.2) and the visual refresh (1.0.I.11), we need a distinctive direction that earns the name without turning the app into a toy.

Functional first, but with style.

## Decision Drivers

* Distinctive — recognizably *OCIDex*, not another generic dark-mode SaaS.
* Functional first — must not fight data-density on tables, lists, detail views.
* Low implementation cost — 1.0.I.11 is targeted polish, not a rewrite.
* Accessible — WCAG 2.1 AA, per ADR-0015.
* Works in both light and dark themes (existing `.light` override).
* Stylistic discipline — the joke should land without becoming the whole product.

## Considered Options

* **A — Pokédex Device Chrome** (literal device frame around the app)
* **B — Field Guide / Entry Cards** (numbered entries + calm chrome) ← **chosen**
* **C — Terminal / Data-Tape** (mono-forward, scanlines, amber-on-charcoal)

## Decision Outcome

Chosen option: **B — Field Guide / Entry Cards**.

Pokédex flavor lives in the *artifact-as-entry* metaphor (each artifact, component, and license has an index number, a type chip, and an entry-card silhouette). The chrome stays calm: a small brand-LED dot, a slim accent rule under page headers, and an entry-card pattern reserved for detail views and the landing-page hero. Everywhere else the app continues to read as a clean data tool.

This is the only option that earns the OCIDex name without compromising the app's day job (browsing dense supply-chain metadata), and the only one cheap enough to fit inside the 1.0.I.11 polish budget.

### Concrete design under Option B

**Palette extension.** Add to the `@theme` block in `web/src/index.css`; existing red/blue primary/secondary are kept as-is.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--color-accent-amber` | `#FFB020` | `#D97706` | Brand LED, entry-number focus, "new" pulse |
| `--color-chrome-deep` | `#1A1F2E` | `#1A1D27` | Sidebar brand-bar trim under the red |
| `--color-entry-edge` | `var(--color-primary)` | `var(--color-primary)` | 2px top edge on entry cards |

Amber is used sparingly — accent only, never as a primary action color.

**Typography.** Three-tier system, scoped to avoid app-wide swaps.

* **Body / UI:** Inter (unchanged).
* **Mono:** JetBrains Mono (unchanged — hashes, PURLs, JSON viewer).
* **Display:** *Space Grotesk* — loaded only for `.brand` (sidebar wordmark, landing hero) and `.entry-number` (the `#000142`-style index badge). Geometric, slightly quirky, pairs cleanly with Inter; subset to Latin to keep payload small.

**Iconography.** Adopt `lucide-solid` and replace the hand-rolled SVGs in `Layout.tsx` (Home, Artifacts, Components, Licenses, Compare, Admin, GitHub, Logout). 1.5px strokes and rounded caps already match the existing style; tree-shaken bundle adds ~3KB per icon. No custom icon set — Lucide covers everything we need.

**Motion guidelines — subtle.**

* Existing 150ms hover/focus transitions stay as the default.
* **New:** one-time `entry-pulse` on the brand LED at app load (1.2s, settles to a steady amber).
* **New:** 200ms `scale(1.02)` + shadow lift on entry-card hover.
* **No** scanlines, parallax, page transitions, or animated route changes. The app should feel responsive, not theatrical.

**Chrome elements introduced.**

1. **Brand LED.** A 6px amber dot left of the `OCIDex` wordmark in `.sidebar-brand`, with the load-time pulse described above.
2. **Entry-card pattern.** Reserved for: artifact detail header, component detail header, license detail header, and landing-page feature cards. Layout:
   * Top-left: `#000142` index badge in Space Grotesk, color `--color-text-muted`, focused state in amber.
   * Top-right: type chip (e.g. `oci-image`, `npm`, `MIT`) using the existing `.badge` token.
   * 2px top edge in `--color-entry-edge` (primary red), faded to transparent across the right 30% of the card.
3. **Page-header accent rule.** Slim 2px gradient rule under `.page-header h2`, red → transparent across the first 120px. Adds rhythm without per-page art.
4. **Sidebar brand-bar.** Existing red `.sidebar-brand` block gets a 1px `--color-chrome-deep` bottom trim — reads like the seam between the Pokédex screen and case.

**Index-number scheme.** Each entity type has its own zero-padded sequence — artifacts `#A000142`, components `#C000142`, licenses `#L000142`. Sequence is derived from the database `id` (or sort order) at render time; not a new persisted column.

### Consequences

* **Good** — Distinctive without sacrificing data-density; Pokédex metaphor lives where it is most visible (entries) and stays out of the way elsewhere.
* **Good** — Implementable inside 1.0.I.11 with edits to `index.css`, `Layout.tsx`, and a small `EntryCard` component. No build-system or framework churn.
* **Good** — Works against existing tokens; light/dark parity comes for free.
* **Good** — Accessibility is a constraint, not a retrofit: amber on dark surface clears AA at body sizes; primary red and amber are not used in combination as a foreground/background pair.
* **Bad** — Less immediately striking than Option A on first load. The metaphor reveals itself on detail pages, not the dashboard.
* **Bad** — Requires editorial discipline: the entry-card pattern must not creep into list rows, modals, or dialogs. A reviewer (or a lint comment in the component) should enforce it.

### Confirmation

Implementation lives in 1.0.I.11. That issue's review should:

1. Compare the rendered detail pages against the entry-card spec above (index badge top-left, type chip top-right, red-fade top edge).
2. Verify both `.light` and dark themes for AA contrast on amber, primary red, and entry-card chrome.
3. Confirm the brand LED pulses once on load and settles, with no continuous animation.
4. Confirm `lucide-solid` icons fully replace hand-rolled SVGs in `Layout.tsx`.
5. Confirm Space Grotesk is loaded only for `.brand` and `.entry-number`.

## Pros and Cons of the Options

### A — Pokédex Device Chrome

* Good, because maximally distinctive — anyone who sees a screenshot knows what app this is.
* Good, because it commits hardest to the name's premise.
* Bad, because device-frame chrome fights data-density: tables in a "screen inset" feel cramped, and every page becomes a diorama.
* Bad, because it ages fast — skeuomorphic device frames are a 2010s dialect.
* Bad, because implementation cost is high (custom hinge/bezel SVG, responsive collapse rules, light-mode reinvention).

### B — Field Guide / Entry Cards *(chosen)*

* Good, because the metaphor (artifacts as field-guide entries) is *true* — it actually maps to the data model, not just the name.
* Good, because the chrome is calm everywhere except detail pages and hero, so dense list views remain dense.
* Good, because it builds on existing tokens, layout, and components instead of replacing them.
* Good, because it scales: same pattern works for artifacts, components, licenses, and any future entity type.
* Bad, because the dashboard and list pages don't carry obvious branding — the identity reveals on click-through.

### C — Terminal / Data-Tape

* Good, because it's authentic to the supply-chain / SBOM audience (developers reading manifests).
* Good, because it's cheap (mono-promotion, an amber accent, a CSS scanline overlay).
* Bad, because it abandons the Pokédex thread that the product name sets up — the wordplay goes unrewarded.
* Bad, because "amber-on-charcoal terminal dev tool" is a saturated aesthetic; nothing about it says *OCIDex* specifically.

## More Information

* Existing design tokens: `web/src/index.css:1-86`
* Current chrome: `web/src/components/Layout.tsx:24-170`
* ADR-0015 — UI / styling and accessibility commitments
* ADR-0012 — SolidJS framework choice
* Implementation issue: `ocidex-6ce.64` (1.0.I.11 — Apply visual identity refresh)
* Landing page consumer: `ocidex-6ce.55` (1.0.I.2 — Public-facing landing page)
