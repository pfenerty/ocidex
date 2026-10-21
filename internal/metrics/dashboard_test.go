package metrics_test

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/matryer/is"
)

// m5Series are the scraped names ADR-0054 M5 lists. The chart's dashboard may
// query only these, and should show every one of them.
var m5Series = []string{
	"http_server_request_duration_seconds",
	"ocidex_jobs_processed_total",
	"ocidex_job_duration_seconds",
	"ocidex_jobs",
	"ocidex_db_pool_connections",
	"ocidex_db_pool_acquires_total",
	"ocidex_db_pool_acquire_wait_seconds_total",
	"ocidex_nats_publishes_total",
	"ocidex_registry_tags_selected",
	"ocidex_registry_tags_skipped_limit",
}

// seriesRe finds metric names in a PromQL expression: a name directly
// followed by a selector or range.
var seriesRe = regexp.MustCompile(`([a-zA-Z_:][a-zA-Z0-9_:]*)\s*[{\[]`)

type dashboard struct {
	UID    string `json:"uid"`
	Panels []struct {
		Type       string `json:"type"`
		Title      string `json:"title"`
		Datasource struct {
			UID string `json:"uid"`
		} `json:"datasource"`
		Targets []struct {
			Expr string `json:"expr"`
		} `json:"targets"`
	} `json:"panels"`
}

// baseSeries strips the histogram suffixes Prometheus adds.
func baseSeries(name string) string {
	for _, suffix := range []string{"_bucket", "_count", "_sum"} {
		if b, ok := strings.CutSuffix(name, suffix); ok && slices.Contains(m5Series, b) {
			return b
		}
	}
	return name
}

func TestDashboardUsesM5Series(t *testing.T) {
	is := is.New(t)
	raw, err := os.ReadFile("../../charts/ocidex/dashboards/ocidex.json")
	is.NoErr(err)
	var d dashboard
	is.NoErr(json.Unmarshal(raw, &d))
	is.Equal(d.UID, "ocidex-overview")

	seen := map[string]bool{}
	for _, p := range d.Panels {
		if p.Type == "row" {
			continue
		}
		if p.Datasource.UID != "${datasource}" {
			t.Errorf("panel %q: datasource %q, want the ${datasource} variable", p.Title, p.Datasource.UID)
		}
		if len(p.Targets) == 0 {
			t.Errorf("panel %q has no queries", p.Title)
		}
		for _, target := range p.Targets {
			if !strings.Contains(target.Expr, `namespace=~"$namespace"`) {
				t.Errorf("panel %q: query ignores the namespace variable: %s", p.Title, target.Expr)
			}
			for _, m := range seriesRe.FindAllStringSubmatch(target.Expr, -1) {
				name := baseSeries(m[1])
				if !slices.Contains(m5Series, name) {
					t.Errorf("panel %q queries %s, which ADR-0054 M5 does not list", p.Title, m[1])
				}
				seen[name] = true
			}
		}
	}
	for _, s := range m5Series {
		if !seen[s] {
			t.Errorf("no panel shows %s", s)
		}
	}
}
