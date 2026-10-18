---
status: "accepted"
date: 2026-10-18
decision-makers: Patrick Fenerty
---

# No squashed migration baseline for 1.0

## Context and Problem Statement

`db/migrations/` holds 79 goose migrations (00001–00079), embedded through `db.Migrations`
and run by `ocidex migrate up` or the chart's migrate hook. 1.0 freezes the upgrade contract
([ADR-052](0052-v1-compatibility.md)): an upgrade into 1.0 comes only from the latest 0.x
minor, and within 1.x any version upgrades directly to any later one.

A squash would replace the history with one baseline, for example `01000_v1_baseline.sql`
generated from `pg_dump --schema-only` of a database migrated to the final 0.x. An empty
database would run only the baseline, and a database already at the final 0.x would be marked
as at the baseline without running it. Should 1.0 ship that baseline, or keep the history?

## Decision Drivers

* A fresh install and an upgraded install must end up with the same schema *and* the same
  seed rows. Today one code path guarantees that, and it must stay true for every 1.x
  migration.
* The 1.0 freeze is the worst time to add risk to the migration path. A baseline bug would
  surface at the first install of the supported release.
* Every promise must be enforceable in CI or by the release checklist (ADR-052).
* Cost has to be real. A squash is worth doing only if keeping the history hurts.

## Considered Options

* Keep the full history (no squash)
* Squash to a `pg_dump --schema-only` baseline at 1.0
* Squash to a hand-curated baseline (schema plus seed rows) with a CI equivalence check

## Decision Outcome

Chosen option: "Keep the full history (no squash)". Keeping it costs almost nothing, and both
squash options add a second install path at the moment the contract freezes.

What the history actually costs, measured on 2026-10-18:

* **Time:** `ocidex migrate up` on an empty PostgreSQL 18 database runs all 79 migrations in
  0.83 s (local, release binary). The integration tests pay it per test database, which is
  noise next to testcontainers start-up.
* **Size:** 79 files. Schema readers want the current shape, and the migrated database (or
  sqlc's `internal/repository/models.go`) gives it to them better than a dump would.

What a baseline would have to get right, beyond the schema:

* **Seed rows.** 00040 inserts the `vuln_refresh_state` singleton the vuln refresh relies
  on. 00008 and 00069 leave a `github:16961380` identity in every fresh database (filed
  separately; see More Information). `--schema-only` drops both, so a dumped baseline is not
  equivalent. A curated one has to track every seed row by hand.
* **Objects a dump renders differently from how they were created.** Function bodies,
  `COMMENT ON` text and column order come back in `pg_dump`'s form. Ownership and grants are
  what `ocidex migrate audit` (the ownership preflight) checks, and a dump taken as one role
  and restored as another changes them.
* **goose bookkeeping.** goose has no "mark applied" step. With 00001–00079 deleted, a
  database at 79 would see the baseline as pending and try to run it against existing tables.
  `runMigrate` would need its own pre-step: at the final 0.x version, insert the baseline row;
  below it, refuse; when empty, run the baseline. That is new code on the one path every
  operator runs.

Down migrations do not change the picture. ADR-052 already says they are not a supported
rollback (00069 and 00070 are lossy), so squashing them away gains nothing an operator can
use.

### Consequences

* Good, because there is one install path. A fresh database is, by construction, an upgraded
  database that started empty.
* Good, because nothing in `runMigrate`, the chart hook or `migrate audit` changes at the
  freeze.
* Good, because a squash stays available later. The upgrade policy leaves room for one at the
  next major (see More Information).
* Bad, because the history keeps growing, and so does the run time. At 0.83 s for 79
  migrations, that is not a concern for 1.x.
* Bad, because a fresh database still carries the historical seed rows, including the
  00008/00069 identity, until a forward migration removes them. The fix for that is a
  migration, not a baseline.

### Confirmation

* No `db/migrations/01000_*` file or baseline logic in `runMigrate` ships in 1.0.
* `docs/UPGRADING.md` keeps the ADR-052 rule that an upgrade into 1.0 comes from the latest
  0.x, which needs nothing from this ADR.

## Pros and Cons of the Options

### Keep the full history (no squash)

* Good, because it is what runs today, in CI and in the release checklist.
* Good, because seed rows, ownership and comments are correct by construction.
* Bad, because 79 files (and growing) is a longer read than one.

### Squash to a `pg_dump --schema-only` baseline at 1.0

* Good, because it is one command to produce.
* Bad, because it is not equivalent: it drops the 00040 seed row, so a fresh install would
  lack `vuln_refresh_state`.
* Bad, because it needs custom goose bookkeeping for databases at the final 0.x.

### Squash to a hand-curated baseline with a CI equivalence check

* Good, because a CI job could compare the baseline-installed database with a
  history-migrated one (`pg_dump --schema-only` diff, plus seed-row counts) and catch drift.
* Bad, because the check is only as good as its list of seed tables, maintained by hand.
* Bad, because the same custom goose bookkeeping is still needed, and every 1.x migration
  would have to be tested on both paths until the next squash.

## More Information

* **Revisit at 2.0.** ADR-052's "into a major only from the latest previous minor" rule is
  what makes a squash possible, so the next chance is the move into 2.0. The procedure then:
  migrate an empty database through the last 1.x; generate the baseline from it, including
  seed rows; add a CI job that diffs a baseline install against a history install; and teach
  `runMigrate` the three cases (empty, at the last 1.x, below it). Only do it if the history
  has started to cost something measurable.
* The fresh-install `github:16961380` identity from 00008 (demoted to viewer by 00079) is
  ocidex-7tss, fixed with a forward migration.
* Related: [ADR-052](0052-v1-compatibility.md) (upgrade policy, forward-only migrations).
