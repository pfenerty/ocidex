package tests

import (
	"database/sql"
	"testing"

	"github.com/matryer/is"
	"github.com/pressly/goose/v3"

	"github.com/pfenerty/ocidex/db"
)

// seededAdminRole reads the role of the account 00008 seeded, by its identity.
func seededAdminRole(t *testing.T, sqlDB *sql.DB) string {
	t.Helper()
	var role string
	err := sqlDB.QueryRowContext(t.Context(), `
		SELECT u.role FROM ocidex_user u
		JOIN user_identity i ON i.user_id = u.id
		WHERE i.provider = 'github' AND i.subject = '16961380'`).Scan(&role)
	if err != nil {
		t.Fatalf("reading seeded account: %v", err)
	}
	return role
}

func countAdmins(t *testing.T, sqlDB *sql.DB) int {
	t.Helper()
	var n int
	if err := sqlDB.QueryRowContext(t.Context(), `SELECT count(*) FROM ocidex_user WHERE role = 'admin'`).Scan(&n); err != nil {
		t.Fatalf("counting admins: %v", err)
	}
	return n
}

func openMigrationDB(t *testing.T) *sql.DB {
	t.Helper()
	connStr, dropDB := newTestDB(t)
	t.Cleanup(dropDB)
	sqlDB, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("opening connection: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	goose.SetBaseFS(db.Migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("setting dialect: %v", err)
	}
	return sqlDB
}

// TestFreshInstallHasNoAdmin covers ocidex-avsz.1: a fresh database carries no
// installation admin, and 00079's Down restores the seeded one.
func TestFreshInstallHasNoAdmin(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	sqlDB := openMigrationDB(t)

	is.NoErr(goose.Up(sqlDB, "migrations"))
	is.Equal(countAdmins(t, sqlDB), 0)

	is.NoErr(goose.DownTo(sqlDB, "migrations", 78))
	is.Equal(seededAdminRole(t, sqlDB), "admin")

	is.NoErr(goose.Up(sqlDB, "migrations"))
	is.Equal(countAdmins(t, sqlDB), 0)
}

// TestSeededAdminKeptWhenUsed: an installation that has signed in with the
// seeded account keeps it as admin across the upgrade.
func TestSeededAdminKeptWhenUsed(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	sqlDB := openMigrationDB(t)

	is.NoErr(goose.UpTo(sqlDB, "migrations", 78))
	_, err := sqlDB.ExecContext(t.Context(), `
		INSERT INTO session (user_id, token_hash, expires_at)
		SELECT user_id, 'h', now() + interval '1 day' FROM user_identity
		WHERE provider = 'github' AND subject = '16961380'`)
	is.NoErr(err)

	is.NoErr(goose.Up(sqlDB, "migrations"))
	is.Equal(seededAdminRole(t, sqlDB), "admin")
}
