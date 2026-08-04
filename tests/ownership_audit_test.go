package tests

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/matryer/is"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/pfenerty/ocidex/internal/dbaudit"
)

// TestOwnershipAudit reproduces the ocidex-63b failure shape: objects created
// out-of-band by a superuser are invisible to ownership-requiring DDL run by
// the app role. The audit must name them, ignore extension members, and go
// quiet once ownership is transferred.
func TestOwnershipAudit(t *testing.T) {
	requireDocker(t)
	is := is.New(t)
	ctx := t.Context()

	pgContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
		postgres.WithDatabase("ocidex_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	is.NoErr(err)
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	superURL, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	is.NoErr(err)
	host, err := pgContainer.Host(ctx)
	is.NoErr(err)
	port, err := pgContainer.MappedPort(ctx, "5432/tcp")
	is.NoErr(err)
	appURL := fmt.Sprintf("postgres://app:app@%s:%s/ocidex_test?sslmode=disable", host, port.Port())

	super, err := sql.Open("pgx", superURL)
	is.NoErr(err)
	defer super.Close()

	// The app role, plus objects the superuser created by hand — exactly the
	// state hand-run psql left in ocidex-dev.
	setup := []string{
		`CREATE ROLE app LOGIN PASSWORD 'app'`,
		`GRANT USAGE, CREATE ON SCHEMA public TO app`,
		`CREATE EXTENSION IF NOT EXISTS pg_trgm`,
		`CREATE TABLE component_rollup (id int)`,
		`CREATE FUNCTION visible_registry_ids(u uuid, b boolean)
		 RETURNS SETOF uuid LANGUAGE sql AS $$ SELECT u WHERE b $$`,
	}
	for _, stmt := range setup {
		_, err = super.ExecContext(ctx, stmt)
		is.NoErr(err)
	}

	app, err := sql.Open("pgx", appURL)
	is.NoErr(err)
	defer app.Close()

	// An object the app role created itself must never be reported.
	_, err = app.ExecContext(ctx, `CREATE TABLE sbom (id int)`)
	is.NoErr(err)

	role, err := dbaudit.CurrentUser(ctx, app)
	is.NoErr(err)
	is.Equal(role, "app")

	objs, err := dbaudit.Misowned(ctx, app)
	is.NoErr(err)

	found := map[string]string{} // name -> kind
	for _, o := range objs {
		t.Logf("misowned: %s public.%s (owner %s)", o.Kind, o.Name, o.Owner)
		found[o.Name] = o.Kind
	}
	is.Equal(found["component_rollup"], "TABLE")
	// Identity arguments carry parameter names when the routine declares them;
	// ALTER FUNCTION accepts that form, which is what makes the rendered
	// statement paste-able.
	is.Equal(found["visible_registry_ids(u uuid, b boolean)"], "FUNCTION")
	_, ok := found["sbom"]
	is.True(!ok) // app-owned table must not be reported
	is.Equal(len(objs), 2)

	// pg_trgm installs ~30 superuser-owned functions in public; they are
	// extension members and EXECUTE is public, so they are not a defect.
	for _, o := range objs {
		is.True(!strings.HasPrefix(o.Name, "similarity"))
		is.True(!strings.HasPrefix(o.Name, "show_trgm"))
	}

	// Repairing ownership — the only fix, and only a superuser can do it —
	// clears the audit.
	for _, o := range objs {
		_, err = super.ExecContext(ctx, o.AlterOwnerSQL("app"))
		is.NoErr(err)
	}
	objs, err = dbaudit.Misowned(ctx, app)
	is.NoErr(err)
	is.Equal(len(objs), 0)
}
