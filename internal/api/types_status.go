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
		ScanJobs   ScanJobsStatus   `json:"scan_jobs"`
		DB         DBStatus         `json:"db"`
	}
}

// EnrichmentStatus describes the enrichment pipeline configuration.
type EnrichmentStatus struct {
	Enabled   bool `json:"enabled"`
	Workers   int  `json:"workers"`
	QueueSize int  `json:"queue_size"`
}

// ScannerStatus describes the scanner configuration.
type ScannerStatus struct {
	Enabled       bool `json:"enabled"`
	PollerEnabled bool `json:"poller_enabled"`
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
	Succeeded24h int64 `json:"succeeded_24h"`
	Failed24h    int64 `json:"failed_24h"`
}

// DBStatus reports database connectivity and latency.
type DBStatus struct {
	OK        bool  `json:"ok"`
	LatencyMs int64 `json:"latency_ms"`
}
