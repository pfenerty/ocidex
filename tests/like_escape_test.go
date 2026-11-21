package tests

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// Search input is matched literally: "_" and "%" are characters, not LIKE
// wildcards (ocidex-4zfn.1). Before like_contains, "foo_bar" also matched
// "fooXbar" and "%" matched every row.
func TestSearchTreatsWildcardsLiterally(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	requireTestInfra(t)
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	is := is.New(t)
	ctx := t.Context()
	q := repository.New(pool)

	names := []string{"foo_bar", "fooXbar", "100% open", "back\\slash", "plain"}
	for _, n := range names {
		_, err := pool.Exec(ctx, `INSERT INTO license (name) VALUES ($1)`, n)
		is.NoErr(err)
		_, err = pool.Exec(ctx, `INSERT INTO artifact (type, name) VALUES ('container', $1)`, n)
		is.NoErr(err)
	}

	tests := []struct {
		query string
		want  []string
	}{
		{"foo_bar", []string{"foo_bar"}},
		{"_", []string{"foo_bar"}},
		{"%", []string{"100% open"}},
		{"0% o", []string{"100% open"}},
		{"\\", []string{"back\\slash"}},
		{"FOO", []string{"foo_bar", "fooXbar"}}, // still case-insensitive
		{"oo", []string{"foo_bar", "fooXbar"}},  // still a substring match
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			is := is.New(t)
			rows, err := q.ListLicenses(ctx, repository.ListLicensesParams{
				IsAdmin:  pgtype.Bool{Bool: true, Valid: true},
				Name:     pgtype.Text{String: tt.query, Valid: true},
				RowLimit: 50,
			})
			is.NoErr(err)
			got := map[string]bool{}
			for _, r := range rows {
				got[r.Name] = true
			}
			is.Equal(len(got), len(tt.want))
			for _, w := range tt.want {
				is.True(got[w])
			}

			n, err := q.CountArtifacts(ctx, repository.CountArtifactsParams{
				IsAdmin: pgtype.Bool{Bool: true, Valid: true},
				Name:    pgtype.Text{String: tt.query, Valid: true},
			})
			is.NoErr(err)
			is.Equal(n, int64(len(tt.want)))
		})
	}
}
