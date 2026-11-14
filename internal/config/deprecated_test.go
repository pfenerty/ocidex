package config

import "testing"

func TestDeprecatedSet(t *testing.T) {
	env := map[string]string{"ENRICHMENT_WORKERS": "4", "ENRICHMENT_MAX_CONCURRENCY": "10"}
	got := DeprecatedSet(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if len(got) != 1 || got[0].Name != "ENRICHMENT_WORKERS" || got[0].Removal != "2.0" {
		t.Fatalf("DeprecatedSet = %+v, want only ENRICHMENT_WORKERS", got)
	}
	if none := DeprecatedSet(func(string) (string, bool) { return "", false }); len(none) != 0 {
		t.Fatalf("unset environment reported %+v", none)
	}
}
