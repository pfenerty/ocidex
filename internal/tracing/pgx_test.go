package tracing_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/tracing"
)

func TestQuerySpanName(t *testing.T) {
	cases := map[string]string{
		"-- name: CountActiveScanJobs :many\nSELECT state FROM scan_jobs": "CountActiveScanJobs",
		"  -- name: GetSBOM :one\nSELECT 1":                               "GetSBOM",
		"select * from sbom where id = $1":                                "SELECT",
		"-- a comment\n\ninsert into t values ($1)":                       "INSERT",
		"BEGIN;": "BEGIN",
		"":       "query",
	}
	for stmt, want := range cases {
		is.New(t).Equal(tracing.QuerySpanName(stmt), want)
	}
}

// TestQuerySpanNameReadsSqlcOutput guards the assumption the names rest on:
// every statement sqlc generates still opens with its "-- name:" line.
func TestQuerySpanNameReadsSqlcOutput(t *testing.T) {
	is := is.New(t)
	files, err := filepath.Glob("../repository/*.sql.go")
	is.NoErr(err)
	is.True(len(files) > 0)
	constRe := regexp.MustCompile("(?m)^const (\\w+) = `([^`]*)`")
	n := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		is.NoErr(err)
		for _, m := range constRe.FindAllStringSubmatch(string(src), -1) {
			n++
			name := tracing.QuerySpanName(m[2])
			if !strings.EqualFold(name, m[1]) {
				t.Errorf("%s: %s is named %q", filepath.Base(f), m[1], name)
			}
		}
	}
	is.True(n > 100) // the whole query set, not a stray match
}
