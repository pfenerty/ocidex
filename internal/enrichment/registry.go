package enrichment

// Registry holds the set of enrichers that the dispatcher will run.
// Register enrichers at startup; pass the registry to NewDispatcher.
type Registry struct {
	enrichers []Enricher
}

// NewRegistry creates an empty enricher registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds an enricher to the registry.
func (r *Registry) Register(e Enricher) {
	r.enrichers = append(r.enrichers, e)
}

// Enrichers returns the registered enrichers in registration order.
func (r *Registry) Enrichers() []Enricher {
	return r.enrichers
}
