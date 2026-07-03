package service

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

func sev(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }

func TestBuildVulnSummary(t *testing.T) {
	is := is.New(t)

	// No rows -> nil.
	is.True(buildVulnSummary(nil) == nil)

	rows := []repository.GetSBOMVulnSummaryRow{
		{Severity: sev("CRITICAL"), Count: 2},
		{Severity: sev("HIGH"), Count: 3},
		{Severity: sev("UNKNOWN"), Count: 1},
		{Severity: pgtype.Text{}, Count: 4}, // null severity folds into Unknown
	}
	vs := buildVulnSummary(rows)
	is.True(vs != nil)
	is.Equal(vs.Critical, 2)
	is.Equal(vs.High, 3)
	is.Equal(vs.Unknown, 5) // 1 explicit + 4 null
	is.Equal(vs.Total, 10)
}

func TestSeverityRank(t *testing.T) {
	is := is.New(t)
	is.True(severityRank("CRITICAL") > severityRank("HIGH"))
	is.True(severityRank("HIGH") > severityRank("MEDIUM"))
	is.True(severityRank("MEDIUM") > severityRank("LOW"))
	is.True(severityRank("LOW") > severityRank("UNKNOWN"))
	is.Equal(severityRank("anything-else"), 0)
}
