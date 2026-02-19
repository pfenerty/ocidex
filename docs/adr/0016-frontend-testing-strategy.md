---
status: "accepted"
date: 2025-06-09
decision-makers: Patrick Fenerty
---

# Choose Frontend Testing Strategy

## Context and Problem Statement

The backend has unit tests (table-driven, `matryer/is`) and integration tests (testcontainers). We need an analogous testing strategy for the frontend that covers component rendering, user interactions, data fetching, and critical user flows. The strategy must integrate with the existing `make test` and CI pipeline. Depends on ADR-0012 (SolidJS) and ADR-0014 (Vite).

## Decision Drivers

* Parity with backend testing philosophy — table-driven, fast, deterministic
* Component-level testing — render components in isolation, assert on DOM output and behavior
* Integration coverage — test data fetching with mocked API responses
* E2E for critical paths — verify full user flows (ingest SBOM → browse artifact → view components)
* CI-friendly — no browser installation required for unit/component tests, headless for E2E
* Framework support — test utilities must work with SolidJS's fine-grained reactivity model

## Considered Options

* Vitest + Solid Testing Library + Playwright + MSW
* Vitest + Solid Testing Library + Cypress
* Vitest + manual DOM assertions + Playwright

## Decision Outcome

Chosen option: "Vitest + Solid Testing Library + Playwright + MSW", because Vitest shares the Vite config (zero extra bundler setup), Solid Testing Library follows the Testing Library "test behavior, not implementation" philosophy adapted for Solid's reactivity, Playwright provides cross-browser E2E with auto-waiting and trace debugging, and MSW intercepts API calls at the network level for both component and E2E tests.

### Consequences

* Good, because Vitest uses the same Vite config — no separate test bundler configuration
* Good, because Solid Testing Library tests behavior (what the user sees and clicks), not implementation details
* Good, because MSW mocks the API at the network level — tests exercise the full data fetching path
* Good, because Playwright provides cross-browser E2E with trace viewer for debugging failures
* Good, because `make test` can run frontend unit tests alongside Go tests
* Neutral, because Solid Testing Library is less mature than React Testing Library — fewer examples
* Bad, because Solid's fine-grained reactivity can make async state assertions tricky (requires `waitFor`)

### Confirmation

`make test` runs both Go and frontend unit/component tests. CI runs Playwright E2E tests against a real API. All component tests use MSW for API mocking.

## Pros and Cons of the Options

### Vitest + Solid Testing Library + Playwright + MSW

* Good, because Vitest uses the same Vite config — zero separate configuration
* Good, because Solid Testing Library follows Testing Library philosophy for SolidJS
* Good, because Playwright provides cross-browser E2E with auto-waiting and trace debugging
* Good, because MSW intercepts API calls at network level in both unit and E2E tests
* Good, because Vitest supports concurrent test execution and native TypeScript
* Neutral, because Solid Testing Library has fewer community examples than React Testing Library
* Bad, because Solid's fine-grained reactivity requires `waitFor` for async assertions

### Vitest + Solid Testing Library + Cypress

* Good, because Cypress has an interactive test runner for debugging
* Good, because Cypress component testing runs in a real browser — higher fidelity
* Bad, because Cypress is slower than Playwright for E2E
* Bad, because Cypress component testing has limited SolidJS support
* Bad, because heavier CI footprint — requires browser installation for component tests too

### Vitest + manual DOM assertions + Playwright

* Good, because zero component testing library dependency
* Good, because full control over test setup
* Bad, because manual DOM assertions are verbose and fragile
* Bad, because no Testing Library utilities (screen queries, user events, accessibility queries)
* Bad, because likely to test implementation details rather than behavior

## More Information

* [Vitest](https://vitest.dev/)
* [Solid Testing Library](https://github.com/solidjs/solid-testing-library)
* [Playwright](https://playwright.dev/)
* [MSW](https://mswjs.io/)
