package enrichment

// Catalog holds the set of enrichers that the dispatcher will run.
// Register enrichers at startup; pass the catalog to NewDispatcher.
type Catalog struct {
	enrichers []Enricher
}

// NewCatalog creates an empty enricher catalog.
func NewCatalog() *Catalog {
	return &Catalog{}
}

// Register adds an enricher to the catalog.
func (r *Catalog) Register(e Enricher) {
	r.enrichers = append(r.enrichers, e)
}

// Enrichers returns the registered enrichers in registration order.
func (r *Catalog) Enrichers() []Enricher {
	return r.enrichers
}
