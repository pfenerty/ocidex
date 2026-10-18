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

func countSeedAccounts(t *testing.T, sqlDB *sql.DB) int {
	t.Helper()
	var n int
	if err := sqlDB.QueryRowContext(t.Context(), `
		SELECT count(*) FROM user_identity
		WHERE provider = 'github' AND subject = '16961380'`).Scan(&n); err != nil {
		t.Fatalf("counting seeded account: %v", err)
	}
	return n
}

// TestFreshInstallHasNoSeedAccount covers ocidex-7tss: a database migrated
// from empty holds no account at all, and 00080's Down restores the viewer
// 00079 left.
func TestFreshInstallHasNoSeedAccount(t *testing.T) {
	requireTestInfra(t)
	is := is.New(t)
	sqlDB := openMigrationDB(t)

	is.NoErr(goose.Up(sqlDB, "migrations"))
	var users int
	is.NoErr(sqlDB.QueryRowContext(t.Context(), `SELECT count(*) FROM ocidex_user`).Scan(&users))
	is.Equal(users, 0)

	is.NoErr(goose.DownTo(sqlDB, "migrations", 79))
	is.Equal(seededAdminRole(t, sqlDB), "viewer")

	is.NoErr(goose.Up(sqlDB, "migrations"))
	is.Equal(countSeedAccounts(t, sqlDB), 0)
}

// TestSeedAccountKeptWhenUsed: each sign of use keeps the seeded account
// through 00080, including a sign-in whose session has since expired and been
// purged, which only the identity's updated_at still records.
func TestSeedAccountKeptWhenUsed(t *testing.T) {
	for name, use := range map[string]string{
		"signed in, session purged": `UPDATE user_identity SET updated_at = updated_at + interval '1 second'
			WHERE provider = 'github' AND subject = '16961380'`,
		"api key": `INSERT INTO api_key (user_id, name, key_hash, prefix)
			SELECT user_id, 'k', 'h', 'ocx_abcd' FROM user_identity
			WHERE provider = 'github' AND subject = '16961380'`,
		"namespace member": `WITH ns AS (INSERT INTO namespace (name, visibility) VALUES ('kept', 'private') RETURNING id)
			INSERT INTO namespace_member (namespace_id, user_id, role)
			SELECT ns.id, i.user_id, 'owner' FROM ns, user_identity i
			WHERE i.provider = 'github' AND i.subject = '16961380'`,
	} {
		t.Run(name, func(t *testing.T) {
			requireTestInfra(t)
			is := is.New(t)
			sqlDB := openMigrationDB(t)

			is.NoErr(goose.UpTo(sqlDB, "migrations", 79))
			_, err := sqlDB.ExecContext(t.Context(), use)
			is.NoErr(err)

			is.NoErr(goose.Up(sqlDB, "migrations"))
			is.Equal(countSeedAccounts(t, sqlDB), 1)
		})
	}
}
