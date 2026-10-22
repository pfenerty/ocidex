package tracing

import (
	"strings"

	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
)

// PoolTracer is the pgx tracer for a pool's ConnConfig.Tracer (ADR-0055 T2):
// one span per query, named by its sqlc query, with db.query.text and never the
// arguments. Like Transport it records on the global TracerProvider, so a pool
// built before Start is still traced once Start runs.
//
// otelpgx's own database metrics are off: ADR-0054 M5 does not list them.
func PoolTracer() pgx.QueryTracer {
	return otelpgx.NewTracer(
		otelpgx.WithMeterProvider(metricnoop.NewMeterProvider()),
		otelpgx.WithSpanNameFunc(QuerySpanName),
	)
}

// QuerySpanName names a statement's span after the sqlc query it came from,
// read from the "-- name: GetSBOM :one" line sqlc puts first. A statement
// without one, such as a migration or a hand-written query, is named by its
// first keyword (SELECT, INSERT, ...), never by its text.
func QuerySpanName(stmt string) string {
	stmt = strings.TrimSpace(stmt)
	if rest, ok := strings.CutPrefix(stmt, "-- name:"); ok {
		if fields := strings.Fields(rest); len(fields) > 0 {
			return fields[0]
		}
	}
	for _, line := range strings.Split(stmt, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		if word, _, _ := strings.Cut(line, " "); word != "" {
			return strings.ToUpper(strings.TrimRight(word, ";("))
		}
	}
	return "query"
}
