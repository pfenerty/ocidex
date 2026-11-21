package api

// ---------------------------------------------------------------------------
// Admin — System Status
// ---------------------------------------------------------------------------

// SystemStatusOutput is the response for GET /api/v1/admin/status.
type SystemStatusOutput struct {
	Body struct {
		Enrichment EnrichmentStatus `json:"enrichment"`
		Scanner    ScannerStatus    `json:"scanner"`
		NATS       NATSStatus       `json:"nats"`
		ScanJobs   ScanJobsStatus   `json:"scanJobs"`
		DB         DBStatus         `json:"db"`
	}
}

// EnrichmentStatus describes the enrichment pipeline configuration.
type EnrichmentStatus struct {
	Enabled bool `json:"enabled"`
	// Deprecated: both echo env vars that no longer size anything.
	// They stay in /api/v1 until 2.0 (ADR-052).
	Workers   int `json:"workers" deprecated:"true" doc:"Deprecated: the value of ENRICHMENT_WORKERS, which no longer changes how many jobs run. Enricher concurrency is ENRICHMENT_MAX_CONCURRENCY on each enricher worker. Removed in 2.0."`
	QueueSize int `json:"queueSize" deprecated:"true" doc:"Deprecated: the value of ENRICHMENT_QUEUE_SIZE, which limits nothing; the queue is the enrichment_jobs table. Removed in 2.0."`
}

// ScannerStatus describes the scanner configuration.
type ScannerStatus struct {
	Enabled       bool `json:"enabled"`
	PollerEnabled bool `json:"pollerEnabled"`
}

// NATSStatus describes the NATS JetStream configuration.
type NATSStatus struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

// ScanJobsStatus summarizes scan pipeline job counts.
type ScanJobsStatus struct {
	Queued       int64 `json:"queued"`
	Running      int64 `json:"running"`
	Succeeded24h int64 `json:"succeeded24h"`
	Failed24h    int64 `json:"failed24h"`
}

// DBStatus reports database connectivity and latency.
type DBStatus struct {
	OK        bool  `json:"ok"`
	LatencyMs int64 `json:"latencyMs"`
}
