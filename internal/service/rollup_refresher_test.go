package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/matryer/is"
	dbfs "github.com/pfenerty/ocidex/db"
	"github.com/pfenerty/ocidex/internal/repository"
)

// boolRow scans a fixed boolean, standing in for pg_try_advisory_xact_lock.
type boolRow struct{ v bool }

func (r boolRow) Scan(dest ...any) error {
	p, ok := dest[0].(*bool)
	if !ok {
		return errors.New("boolRow: destination is not *bool")
	}
	*p = r.v
	return nil
}

// refreshTx records every statement a refresh pass issues, in order, so tests
// can assert on the sequence rather than just the endpoints.
type refreshTx struct {
	fakeTx
	stmts     []string
	committed bool
}

func newRefreshTx(lockAcquired bool) *refreshTx {
	tx := &refreshTx{}
	tx.queryRowFn = func(_ context.Context, sql string, _ ...any) pgx.Row {
		tx.stmts = append(tx.stmts, sql)
		return boolRow{v: lockAcquired}
	}
	tx.execFn = func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
		tx.stmts = append(tx.stmts, sql)
		return pgconn.CommandTag{}, nil
	}
	tx.commitFn = func(context.Context) error {
		tx.committed = true
		return nil
	}
	return tx
}

// firstIndex reports the position of the first recorded statement containing
// substr, or -1.
func (tx *refreshTx) firstIndex(substr string) int {
	for i, s := range tx.stmts {
		if strings.Contains(s, substr) {
			return i
		}
	}
	return -1
}

func refresherFor(tx pgx.Tx) *RollupRefresher {
	db := &fakeDB{beginFn: func(context.Context) (pgx.Tx, error) { return tx, nil }}
	return NewRollupRefresher(db, time.Hour, discardLogger())
}

// The rollups are shared database state, so two replicas refreshing at once
// would duplicate minutes of aggregate work for an identical result. Losing the
// advisory lock is a normal outcome, not an error, and must cost nothing.
func TestRollupRefreshSkipsWhenAnotherReplicaHoldsTheLock(t *testing.T) {
	is := is.New(t)

	tx := newRefreshTx(false)
	ran, err := refresherFor(tx).refresh(context.Background())

	is.NoErr(err)
	is.True(!ran)
	is.Equal(tx.firstIndex("CREATE TEMP TABLE"), -1)
	is.Equal(tx.firstIndex("TRUNCATE"), -1)
	is.True(!tx.committed)
}

// The whole point of staging into temp tables is that the expensive aggregates
// run before anything takes a lock on a live rollup. If a TRUNCATE ever moved
// ahead of the last CREATE TEMP TABLE, the list pages would block for the
// minutes those aggregates take instead of the fraction of a second the swap
// takes — the regression this test exists to catch.
func TestRollupRefreshBuildsEverySnapshotBeforeTakingAnyTableLock(t *testing.T) {
	is := is.New(t)

	tx := newRefreshTx(true)
	ran, err := refresherFor(tx).refresh(context.Background())

	is.NoErr(err)
	is.True(ran)
	is.True(tx.committed)

	var lastBuild, firstTruncate int
	for i, s := range tx.stmts {
		if strings.Contains(s, "CREATE TEMP TABLE") {
			lastBuild = i
		}
	}
	firstTruncate = tx.firstIndex("TRUNCATE")
	is.True(firstTruncate > 0)
	is.True(lastBuild < firstTruncate)
}

// Every rollup is rebuilt in one pass, and each rebuild is a truncate followed
// by a repopulate. A table that was truncated but not refilled would serve an
// empty list page.
func TestRollupRefreshTruncatesAndRepopulatesEveryRollup(t *testing.T) {
	is := is.New(t)

	tx := newRefreshTx(true)
	_, err := refresherFor(tx).refresh(context.Background())
	is.NoErr(err)

	for _, table := range []string{"component_rollup", "license_rollup", "vuln_rollup", "sbom_vuln_rollup"} {
		is.True(tx.firstIndex("CREATE TEMP TABLE tmp_"+table) >= 0)
		truncate := tx.firstIndex("TRUNCATE " + table)
		insert := tx.firstIndex("INSERT INTO " + table)
		is.True(truncate >= 0)
		is.True(insert > truncate)
	}
}

// TRUNCATE queues ahead of every reader that arrives after it, so a pass that
// waits indefinitely for the lock would stall the list pages it exists to make
// fast. The bounded wait must be in place before the first truncate, not after.
func TestRollupRefreshBoundsTheSwapLockWait(t *testing.T) {
	is := is.New(t)

	tx := newRefreshTx(true)
	_, err := refresherFor(tx).refresh(context.Background())
	is.NoErr(err)

	lockTimeout := tx.firstIndex("lock_timeout")
	is.True(lockTimeout >= 0)
	is.True(lockTimeout < tx.firstIndex("TRUNCATE"))
}

// A pass that fails after truncating must not leave the rollups empty. Rolling
// the whole pass back into one transaction is what guarantees that, so a failed
// swap must not commit.
func TestRollupRefreshDoesNotCommitAPartialSwap(t *testing.T) {
	is := is.New(t)

	boom := errors.New("disk full")
	tx := newRefreshTx(true)
	tx.execFn = func(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
		tx.stmts = append(tx.stmts, sql)
		if strings.HasPrefix(sql, "INSERT INTO license_rollup") {
			return pgconn.CommandTag{}, boom
		}
		return pgconn.CommandTag{}, nil
	}

	ran, err := refresherFor(tx).refresh(context.Background())

	is.True(errors.Is(err, boom))
	is.True(!ran)
	is.True(!tx.committed)
}

// markRow scans a watermark, standing in for the count/max over sbom.
type markRow struct{ w repository.RollupWatermark }

func (r markRow) Scan(dest ...any) error {
	n, ok := dest[0].(*int64)
	if !ok {
		return errors.New("markRow: first destination is not *int64")
	}
	at, ok := dest[1].(*time.Time)
	if !ok {
		return errors.New("markRow: second destination is not *time.Time")
	}
	*n, *at = r.w.SBOMs, r.w.Latest
	return nil
}

func markAt(n int64) repository.RollupWatermark {
	return repository.RollupWatermark{SBOMs: n, Latest: time.Unix(n, 0).UTC()}
}

// gatedRefresher returns a refresher whose pool answers watermark reads and
// whose transactions are tx, plus a way to age the last pass.
func gatedRefresher(tx pgx.Tx, mark repository.RollupWatermark) *RollupRefresher {
	db := &fakeDB{
		beginFn: func(context.Context) (pgx.Tx, error) { return tx, nil },
		queryRowFn: func(context.Context, string, ...any) pgx.Row {
			return markRow{w: mark}
		},
	}
	return NewRollupRefresher(db, time.Hour, discardLogger())
}

// Nothing has been built yet when the process starts, so the first tick must
// rebuild regardless of what the watermark says.
func TestRollupRefreshRunsOnStartup(t *testing.T) {
	is := is.New(t)
	r := NewRollupRefresher(&fakeDB{}, time.Hour, discardLogger())
	is.Equal(r.dueReason(markAt(1), true), "startup")
}

// A registry scan moves the watermark continuously. Without a floor on the gap
// between passes, the refresher would rebuild back to back for the duration of
// the scan and permanently occupy the two-connection background pool.
func TestRollupRefreshDebouncesRapidIngest(t *testing.T) {
	is := is.New(t)
	r := NewRollupRefresher(&fakeDB{}, time.Hour, discardLogger())
	r.recordPass(markAt(1), true)

	is.Equal(r.dueReason(markAt(2), true), "")

	r.lastPass = time.Now().Add(-r.minGap - time.Second)
	is.Equal(r.dueReason(markAt(2), true), "ingest")
}

// An unchanged watermark means no SBOM has been ingested, so the component and
// license rollups cannot have changed. The interval still has to fire, because
// vulnerability matches appear when the feed updates with no SBOM involved —
// which is exactly what the watermark cannot see.
func TestRollupRefreshFallsBackToTheIntervalWhenNoSBOMsHaveLanded(t *testing.T) {
	is := is.New(t)
	r := NewRollupRefresher(&fakeDB{}, time.Hour, discardLogger())
	r.recordPass(markAt(1), true)

	r.lastPass = time.Now().Add(-r.minGap - time.Second)
	is.Equal(r.dueReason(markAt(1), true), "")

	r.lastPass = time.Now().Add(-r.interval - time.Second)
	is.Equal(r.dueReason(markAt(1), true), "backstop")
}

// The watermark is an optimisation. If it cannot be read, the rollups must still
// be rebuilt on the interval — but an unreadable watermark is not itself
// evidence that anything changed, so it must not trigger a pass on its own.
func TestRollupRefreshBackstopSurvivesAWatermarkReadFailure(t *testing.T) {
	is := is.New(t)
	r := NewRollupRefresher(&fakeDB{}, time.Hour, discardLogger())
	r.recordPass(markAt(1), true)

	r.lastPass = time.Now().Add(-r.interval - time.Second)
	is.Equal(r.dueReason(repository.RollupWatermark{}, false), "backstop")

	r.lastPass = time.Now().Add(-r.minGap - time.Second)
	is.Equal(r.dueReason(repository.RollupWatermark{}, false), "")
}

// Callers that have just written an SBOM need the rollups to reflect it now,
// not after the poll interval. RefreshNow is that escape hatch, so the gating
// that would otherwise defer the pass must not apply to it.
func TestRefreshNowIgnoresTheGating(t *testing.T) {
	is := is.New(t)

	tx := newRefreshTx(true)
	r := gatedRefresher(tx, markAt(1))
	r.recordPass(markAt(1), true)
	is.Equal(r.dueReason(markAt(1), true), "") // gating would defer this pass

	ran, err := r.RefreshNow(context.Background())

	is.NoErr(err)
	is.True(ran)
	is.True(tx.committed)
}

func TestNewRollupRefresherDefaultsInterval(t *testing.T) {
	is := is.New(t)
	is.Equal(NewRollupRefresher(&fakeDB{}, 0, discardLogger()).interval, RollupRefreshInterval)
	is.Equal(NewRollupRefresher(&fakeDB{}, -time.Second, discardLogger()).interval, RollupRefreshInterval)
}

// The seeding INSERT in the migration and the aggregate the refresher runs are
// two copies of one query, and rollup_refresh.go's header comment makes keeping
// them in step normative. The failure mode is nasty precisely because it is
// quiet: a divergence leaves the rollup correct immediately after the migration
// and wrong after the first refresh pass, with nothing in between to notice.
//
// Only sbom_vuln_rollup (ocidex-unn8.7) is checked. The other three were seeded
// by 00051 keyed on registry_id and rekeyed to namespace_id by 00053, so their
// migration text is a historical record rather than a current definition — the
// aggregate consts are the live truth for those. This one was authored against
// the current schema, so the two texts can and must agree.
func TestSBOMVulnRollupSeedMatchesTheRefreshAggregate(t *testing.T) {
	is := is.New(t)

	aggregate, ok := repository.RollupAggregate("sbom_vuln_rollup")
	is.True(ok) // sbom_vuln_rollup must be a refresh target, not just a table

	raw, err := dbfs.Migrations.ReadFile("migrations/00063_sbom_vuln_rollup.sql")
	is.NoErr(err)

	const insertPrefix = "INSERT INTO sbom_vuln_rollup (sbom_id, namespace_id, critical, high, medium, low, unknown)"
	start := strings.Index(string(raw), insertPrefix)
	is.True(start >= 0) // the migration must still seed the table
	body := string(raw)[start+len(insertPrefix):]
	end := strings.Index(body, ";")
	is.True(end >= 0)

	is.Equal(normalizeSQL(body[:end]), normalizeSQL(aggregate))
}

// normalizeSQL reduces a statement to the parts that change its meaning:
// comments and layout are dropped so the comparison is about the query, not
// about how either copy happens to be indented.
func normalizeSQL(s string) string {
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		kept = append(kept, line)
	}
	return strings.Join(strings.Fields(strings.Join(kept, " ")), " ")
}
