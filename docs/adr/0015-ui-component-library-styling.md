---
status: "accepted"
date: 2025-06-09
decision-makers: Patrick Fenerty
---

# Choose UI Component Library and Styling Approach

## Context and Problem Statement

The OCIDex frontend is a data-heavy dashboard: artifact tables, SBOM detail views, component search with filters, license listings, and changelog diffs. We need a styling approach and optionally a component library that provides accessible, consistent UI primitives (tables, modals, dropdowns, tabs) without imposing heavy design opinions. Depends on ADR-0012 (SolidJS).

## Decision Drivers

* Accessibility — components must meet WCAG 2.1 AA (keyboard navigation, ARIA attributes, focus management)
* Headless over styled — prefer unstyled primitives we can theme ourselves over opinionated design systems
* Data table support — first-class support for sortable, filterable, paginated tables (core UI element)
* Framework-native — components must be built for SolidJS, not framework-agnostic wrappers
* Utility-first CSS — prefer composable utility classes over semantic CSS or CSS-in-JS runtime overhead
* Copy-paste ownership — prefer patterns where component source lives in our repo over black-box npm packages

## Considered Options

* Tailwind CSS + Kobalte + TanStack Table
* Tailwind CSS + custom headless primitives
* CSS Modules (no component library)
* DaisyUI (Tailwind component classes)

## Decision Outcome

Chosen option: "Tailwind CSS + Kobalte + TanStack Table", because Tailwind provides composable, tree-shakeable utility-first styling with zero runtime overhead; Kobalte provides accessible headless UI primitives designed specifically for SolidJS (modals, dropdowns, tabs, tooltips); and TanStack Table's Solid adapter provides headless data table primitives for sortable, filterable, paginated tables — the core UI element of the dashboard.

### Consequences

* Good, because Kobalte handles ARIA attributes, keyboard navigation, and focus trapping — no manual accessibility implementation
* Good, because Tailwind utilities are composable and produce zero unused CSS in production via purging
* Good, because TanStack Table is headless — we control the DOM and styling while it manages sort/filter/pagination state
* Good, because all three are headless/utility-first — full control over appearance with no design lock-in
* Good, because Kobalte is designed for SolidJS — reactivity integration is native, not adapted
* Neutral, because Kobalte's component count is smaller than Radix — may need to build some primitives manually
* Bad, because Tailwind utility classes require learning the vocabulary (offset by excellent IDE integration)

### Confirmation

All interactive components (modals, dropdowns, tabs) pass axe-core accessibility audit. No runtime CSS-in-JS in the bundle. Data tables use TanStack Table for sort/filter/pagination.

## Pros and Cons of the Options

### Tailwind CSS + Kobalte + TanStack Table

* Good, because Kobalte provides accessible headless primitives designed for SolidJS
* Good, because Tailwind utility classes are composable and tree-shakeable
* Good, because TanStack Table (Solid adapter) provides headless data table with sort/filter/pagination
* Good, because headless primitives + Tailwind = full control over appearance
* Good, because Kobalte handles ARIA, keyboard navigation, and focus trapping correctly
* Neutral, because Kobalte's component count is smaller than Radix
* Bad, because Tailwind requires learning utility class vocabulary

### Tailwind CSS + custom headless primitives

* Good, because full control — build exactly what's needed
* Good, because zero external component dependencies
* Bad, because building accessible primitives (focus trapping, ARIA state machines) is difficult and error-prone
* Bad, because significantly slower development velocity — reinventing what Kobalte provides
* Bad, because likely to have accessibility gaps without specialized testing

### CSS Modules (no component library)

* Good, because zero additional dependencies
* Good, because scoped class names prevent collisions
* Bad, because no headless component primitives — must build all accessibility handling manually
* Bad, because more CSS to write and maintain — slower development
* Bad, because no utility composition — each component needs bespoke styles

### DaisyUI (Tailwind component classes)

* Good, because pre-built semantic class names accelerate prototyping
* Good, because theme system with built-in themes
* Bad, because opinionated design — harder to customize beyond theme variables
* Bad, because class-based components don't handle accessibility (no ARIA, no keyboard navigation)
* Bad, because abstracts away Tailwind utilities behind semantic names — fights the utility-first model

## More Information

* [Kobalte](https://kobalte.dev/) — accessible headless UI for SolidJS
* [TanStack Table](https://tanstack.com/table/latest) — headless data table for any framework
* [Tailwind CSS](https://tailwindcss.com/)
