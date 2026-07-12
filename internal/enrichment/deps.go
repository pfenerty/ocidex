package enrichment

// rootEnrichers are enqueued directly on SBOM ingest — they have no
// prerequisite on another enricher's output.
var rootEnrichers = []string{"user", "oci-metadata", "provenance"}

// enricherDeps maps an enricher name to the prerequisite enrichers that
// must reach status=success before it can be enqueued. Enrichers not
// present here are roots. Dependent enqueueing on completion is handled
// by the worker (ocidex-2jb.2); this is purely the declared graph.
var enricherDeps = map[string][]string{
	"git": {"oci-metadata"},
}

// Dependents returns the enrichers that declare name as a prerequisite.
func Dependents(name string) []string {
	var out []string
	for enricher, deps := range enricherDeps {
		for _, d := range deps {
			if d == name {
				out = append(out, enricher)
				break
			}
		}
	}
	return out
}

// Prerequisites returns the prerequisite enrichers for name, or nil if
// name is a root enricher.
func Prerequisites(name string) []string {
	return enricherDeps[name]
}
