package dbaudit

import (
	"strings"
	"testing"

	"github.com/matryer/is"
)

func TestAlterOwnerSQL(t *testing.T) {
	tests := []struct {
		name string
		obj  Object
		role string
		want string
	}{
		{
			name: "table",
			obj:  Object{Kind: "TABLE", Name: "component_rollup", Owner: "postgres"},
			role: "ocidex",
			want: "ALTER TABLE public.component_rollup OWNER TO ocidex;",
		},
		{
			name: "function carries its argument list",
			obj:  Object{Kind: "FUNCTION", Name: "visible_registry_ids(uuid, boolean)", Owner: "postgres"},
			role: "ocidex",
			want: "ALTER FUNCTION public.visible_registry_ids(uuid, boolean) OWNER TO ocidex;",
		},
		{
			name: "multi-word kind stays intact",
			obj:  Object{Kind: "MATERIALIZED VIEW", Name: "stats_cache", Owner: "postgres"},
			role: "ocidex",
			want: "ALTER MATERIALIZED VIEW public.stats_cache OWNER TO ocidex;",
		},
		{
			name: "role needing quoting is quoted",
			obj:  Object{Kind: "TABLE", Name: "sbom", Owner: "postgres"},
			role: "ocidex-app",
			want: `ALTER TABLE public.sbom OWNER TO "ocidex-app";`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(tt.obj.AlterOwnerSQL(tt.role), tt.want)
		})
	}
}

func TestReportListsEveryObjectAndItsFix(t *testing.T) {
	is := is.New(t)

	objs := []Object{
		{Kind: "FUNCTION", Name: "visible_registry_ids(uuid, boolean)", Owner: "postgres"},
		{Kind: "TABLE", Name: "component_rollup", Owner: "postgres"},
	}
	got := Report(objs, "ocidex")

	is.True(strings.Contains(got, "2 public-schema object(s)"))
	for _, o := range objs {
		is.True(strings.Contains(got, o.Name))
		is.True(strings.Contains(got, o.AlterOwnerSQL("ocidex")))
	}
}

func TestQuoteIdent(t *testing.T) {
	is := is.New(t)

	is.Equal(quoteIdent("ocidex"), "ocidex")
	is.Equal(quoteIdent("ocidex_app"), "ocidex_app")
	is.Equal(quoteIdent("app2"), "app2")
	is.Equal(quoteIdent("ocidex-app"), `"ocidex-app"`)
	is.Equal(quoteIdent("Ocidex"), `"Ocidex"`)
	is.Equal(quoteIdent("2fast"), `"2fast"`)
	is.Equal(quoteIdent(`we"ird`), `"we""ird"`)
}
