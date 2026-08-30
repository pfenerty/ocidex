# Frontend Development

- **Framework:** SolidJS (not React — no virtual DOM, fine-grained reactivity)
- **Build:** Vite (`make frontend` to build, `make frontend-dev` for dev server)
- **API proxy:** Dev server proxies `/api/*` to `localhost:8080`
- **Styling:** Tailwind CSS
- **Testing:** Vitest + Solid Testing Library (`make frontend-test`)

After any frontend change, run `make frontend-lint-fix` to auto-fix ESLint errors, then
`make frontend-lint` to verify none remain.

## Verify UI changes in a browser, not only in Vitest

A CSS or markup change that passes `make frontend-test` can still be invisible or
wrong on screen — the app has shipped several dead class names (`tab-btn`,
`tab-active`, `btn-secondary`) and two font tokens that were declared for the
whole app but never fetched. Those all pass unit tests, because a stylesheet that
does nothing is not an assertion failure. **Look at the page.**

There are two rigs. Pick by whether the page needs a signed-in user.

**Auth-gated pages** (`/dashboard`, `/clusters`, `/admin`, anything behind a
user) — and **anything touching a backend change on your branch**:

```bash
flox activate -- make dev-auth-up          # postgres + nats + this branch's API on :8080
flox activate -- make frontend-dev-auth    # :3200, signed in as a local admin
```

No docker: `postgresql` and `nats-server` are native binaries in the Flox
environment, and `scripts/dev-auth.sh` runs the whole stack out of `.dev/`.
Auth is not a bypass — `internal/api/middleware.go` already accepts
`Authorization: Bearer <api-key>` as equivalent to a session, so the rig mints a
fully-capable key and the dev vite config presents it. Writes are safe: the
database is a throwaway. `make dev-auth-reset` starts it over.

`up` finishes by seeding a corpus (`scripts/dev-fixtures.py`, also reachable on
its own as `make dev-auth-fixtures`) — 10 SBOMs over 5 artifacts in two
namespaces, all five ADR-037 signing statuses including a drift *within* one
artifact, two flavors plus one deliberate `unknown`, 6 CVEs wired to purls the
corpus really contains, and a cluster whose 9 workloads cover all three ADR-044
match states. Without it the rig renders nothing: every page it exists to
unblock showed its empty state, so `/clusters/:id` — the surface most in need of
a browser — was unverifiable. Two traps it encodes, both of which read as
database bugs: `/api/v1/artifacts` defaults to `sufficient=true`, so an
un-enriched SBOM is invisible; and `/vulnerabilities` INNER JOINs `vuln_rollup`,
so a vulnerability with no rollup row does not appear at all. The seeder writes
both. It is idempotent — every digest derives from the artifact's identity, so a
re-run is a no-op under the `sbom.digest` UNIQUE constraint.

**Public pages, against the real corpus** — prod data, no local backend needed:

```bash
flox activate -- make frontend-dev-live   # :3100, local frontend + prod data
```

The table below applies to the **prod-proxied** rig only; the local auth rig has
none of these limits, at the cost of an empty database you seed yourself.

Then drive either with the Firefox DevTools MCP — `navigate_page` to the right
port, `evaluate_script` for computed styles, and
`screenshot_page` to actually look. Assert on computed values, not on the
stylesheet source:

```js
// what shipped, not what was written
getComputedStyle(document.querySelector(".page-header h2")).fontSize
await document.fonts.ready; [...document.fonts].map(f => f.family + ":" + f.status)
```

A font only reports `loaded` once some element on the current page uses it, so
check `--font-mono` on a page that actually renders a digest or purl.

| Limit | Why | Consequence |
|---|---|---|
| Signed out only | the prod session cookie is scoped to `ocidex.app` and does not travel to `localhost` | `/dashboard`, `/clusters`, `/admin` redirect to login — use `make frontend-dev-auth` for those, never a copied prod cookie |
| Read only | requests reach **production** | never point it at a write flow, and never add credentials |
| Frontend only | prod runs the deployed API, not your branch | a backend change (new field, new pagination) is invisible until the branch deploys — say so in the issue rather than claiming it was verified |

Pair this with a **contract test** whenever the bug class is "the CSS silently did
nothing": `fontContract.test.ts`, `typeScale.test.ts` and
`components/ui/tabBarContract.test.ts` each read the stylesheet and fail if a
token or class name loses its counterpart. The browser catches it once; the
contract test keeps it caught.
