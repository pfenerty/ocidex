package config_test

import (
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pfenerty/ocidex/internal/config"
)

// readOutsideStructs are documented variables no config struct declares, each
// read with os.Getenv where it is used. Every entry names its reader, so one
// that stops being read can be found and dropped from the docs.
var readOutsideStructs = map[string]string{
	"SCAN_IMAGE":                  "cmd/scanner-worker --once",
	"SCAN_REGISTRY_ID":            "cmd/scanner-worker --once",
	"SCAN_INSECURE":               "cmd/scanner-worker --once",
	"SCAN_AUTH_USERNAME":          "cmd/scanner-worker --once",
	"SCAN_AUTH_TOKEN":             "cmd/scanner-worker --once",
	"ENRICH_SBOM_ID":              "internal/worker/enrichment --once",
	"OTEL_TRACES_EXPORTER":        "internal/tracing",
	"OTEL_TRACES_SAMPLER":         "internal/tracing, then the OpenTelemetry SDK",
	"OTEL_TRACES_SAMPLER_ARG":     "the OpenTelemetry SDK",
	"OTEL_METRICS_EXPORTER":       "internal/metrics",
	"OTEL_EXPORTER_OTLP_ENDPOINT": "the OpenTelemetry SDK",
	"OTEL_RESOURCE_ATTRIBUTES":    "the OpenTelemetry SDK",
}

// TestEnvDocsMatchStructs covers ocidex-vvw6.2, now against EnvDocs, the source of
// the docs site's configuration reference (ocidex-mxy0.8): every env-tagged field
// of every config struct is described, and every described variable is one a
// struct declares or one readOutsideStructs accounts for. Documentation drifted
// both ways before (SCANNER_WORKERS outlived its code; SCANNER_POLL_INTERVAL was
// never written down); this turns either into a failing test.
func TestEnvDocsMatchStructs(t *testing.T) {
	declared := map[string]bool{}
	for _, v := range config.DocumentedStructs() {
		collectEnvTags(reflect.TypeOf(v), declared)
	}
	if len(declared) < 50 {
		t.Fatalf("found only %d env-tagged fields; the reflection walk is broken", len(declared))
	}

	documented := map[string]bool{}
	for _, d := range config.EnvDocs {
		if documented[d.Name] {
			t.Errorf("%s is described twice in EnvDocs", d.Name)
		}
		documented[d.Name] = true
		if strings.TrimSpace(d.Description) == "" || d.Group == "" {
			t.Errorf("%s has an empty description or group in EnvDocs", d.Name)
		}
	}

	for _, name := range sortedKeys(declared) {
		if !documented[name] {
			t.Errorf("%s is read by a config struct but not described in EnvDocs", name)
		}
	}
	for _, name := range sortedKeys(documented) {
		if !declared[name] && readOutsideStructs[name] == "" {
			t.Errorf("%s is described in EnvDocs but no config struct reads it", name)
		}
	}
	for name, reader := range readOutsideStructs {
		if declared[name] {
			t.Errorf("%s is now a struct field; drop it from readOutsideStructs (%s)", name, reader)
		}
		if !documented[name] {
			t.Errorf("%s is in readOutsideStructs but not described in EnvDocs", name)
		}
	}
}

// TestHardeningChecklistNamesDocumentedVariables covers ocidex-vvw6.4: every
// variable the docs site's production hardening checklist names is one EnvDocs
// describes, so the checklist cannot recommend a setting that does not exist or
// has been renamed.
func TestHardeningChecklistNamesDocumentedVariables(t *testing.T) {
	page, err := os.ReadFile("../../site/src/content/docs/guides/operate/production.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(page), "\n## Production hardening checklist\n")
	if !ok {
		t.Fatal("production.md has no \"## Production hardening checklist\" section")
	}
	section, _, _ = strings.Cut(section, "\n## ")

	documented := map[string]bool{}
	for _, d := range config.EnvDocs {
		documented[d.Name] = true
	}
	named := documentedVariables(section)
	if len(named) < 15 {
		t.Fatalf("the checklist names only %d variables; the parse is broken", len(named))
	}
	for _, name := range sortedKeys(named) {
		if !documented[name] {
			t.Errorf("the hardening checklist names %s, which EnvDocs does not describe", name)
		}
	}
}

// collectEnvTags adds every env tag in typ, descending into nested structs.
func collectEnvTags(typ reflect.Type, into map[string]bool) {
	for f := range typ.Fields() {
		if tag, ok := f.Tag.Lookup("env"); ok {
			if name, _, _ := strings.Cut(tag, ","); name != "" {
				into[name] = true
			}
		}
		if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == typ.PkgPath() {
			collectEnvTags(f.Type, into)
		}
	}
}

// docRow is a table row's first cell; docName is a backticked variable in it.
// A cell can name several (`OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`).
var (
	docRow  = regexp.MustCompile(`(?m)^\|([^|]*)\|`)
	docName = regexp.MustCompile("`([A-Z][A-Z0-9_]+)`")
)

func documentedVariables(doc string) map[string]bool {
	out := map[string]bool{}
	for _, row := range docRow.FindAllStringSubmatch(doc, -1) {
		for _, m := range docName.FindAllStringSubmatch(row[1], -1) {
			out[m[1]] = true
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
