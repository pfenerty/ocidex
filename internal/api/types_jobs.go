package api

// ---------------------------------------------------------------------------
// Scan Jobs
// ---------------------------------------------------------------------------

// ScanJobResponse is the public representation of a scan pipeline job.
type ScanJobResponse struct {
	ID            string  `json:"id" doc:"Job UUID"`
	RegistryID    *string `json:"registryId,omitempty" doc:"Source registry UUID"`
	Repository    string  `json:"repository"`
	Digest        string  `json:"digest"`
	Tag           *string `json:"tag,omitempty"`
	State         string  `json:"state" enum:"queued,running,succeeded,failed,pruned"`
	Attempts      int32   `json:"attempts"`
	LastError     *string `json:"lastError,omitempty"`
	NATSMsgID     *string `json:"natsMsgId,omitempty" doc:"NATS deduplication message ID"`
	SbomID        *string `json:"sbomId,omitempty" doc:"Resulting SBOM UUID on success"`
	CreatedAt     string  `json:"createdAt"`
	StartedAt     *string `json:"startedAt,omitempty"`
	LastAttemptAt *string `json:"lastAttemptAt,omitempty"`
	FinishedAt    *string `json:"finishedAt,omitempty"`
	WorkerID      *string `json:"workerId,omitempty" doc:"Pod hostname that is processing this job"`
}

// ListScanJobsInput is the request for GET /api/v1/jobs.
type ListScanJobsInput struct {
	PaginationParams
	State string `query:"state" enum:"queued,running,succeeded,failed,pruned" doc:"Filter by job state"`
}

// ListScanJobsOutput is the response for GET /api/v1/jobs.
type ListScanJobsOutput struct {
	Body struct {
		Data       []ScanJobResponse `json:"data"`
		Pagination PaginationMeta    `json:"pagination"`
	}
}

// GetScanJobInput is the request for GET /api/v1/jobs/{id}.
type GetScanJobInput struct {
	ID string `path:"id" doc:"Job UUID"`
}

// GetScanJobOutput is the response for GET /api/v1/jobs/{id}.
type GetScanJobOutput struct {
	Body ScanJobResponse
}

// RetryScanJobInput is the request for POST /api/v1/admin/jobs/{id}/retry.
type RetryScanJobInput struct {
	ID string `path:"id" doc:"Failed scan job UUID to reset back to 'queued'"`
}

// CancelScanJobInput is the request for POST /api/v1/admin/jobs/{id}/cancel.
type CancelScanJobInput struct {
	ID string `path:"id" doc:"Queued scan job UUID to cancel"`
}

// RetryAllFailedScanJobsOutput is the response for POST /api/v1/admin/jobs/retry-failed.
type RetryAllFailedScanJobsOutput struct {
	Body struct {
		Count int64 `json:"count" doc:"Number of rows transitioned from 'failed' to 'queued'"`
	}
}

// EnrichmentJobResponse is the public representation of an enrichment pipeline job.
type EnrichmentJobResponse struct {
	ID            string  `json:"id" doc:"Job UUID"`
	SbomID        *string `json:"sbomId,omitempty" doc:"SBOM being enriched"`
	EnricherName  string  `json:"enricherName" doc:"Which enricher this job runs" enum:"user,oci-metadata,provenance"`
	State         string  `json:"state" enum:"queued,running,succeeded,failed"`
	Attempts      int32   `json:"attempts"`
	LastError     *string `json:"lastError,omitempty"`
	WorkerID      *string `json:"workerId,omitempty" doc:"Pod hostname that is processing this job"`
	SbomDigest    *string `json:"sbomDigest,omitempty" doc:"Digest of the SBOM's image, for display"`
	ArtifactName  *string `json:"artifactName,omitempty" doc:"Name of the artifact, for display"`
	CreatedAt     string  `json:"createdAt"`
	StartedAt     *string `json:"startedAt,omitempty"`
	LastAttemptAt *string `json:"lastAttemptAt,omitempty"`
	FinishedAt    *string `json:"finishedAt,omitempty"`
}

// ListEnrichmentJobsInput is the request for GET /api/v1/enrichment-jobs.
type ListEnrichmentJobsInput struct {
	PaginationParams
	State        string `query:"state" enum:"queued,running,succeeded,failed" doc:"Filter by job state"`
	EnricherName string `query:"enricher_name" enum:"user,oci-metadata,provenance" doc:"Filter by enricher"`
}

// ListEnrichmentJobsOutput is the response for GET /api/v1/enrichment-jobs.
type ListEnrichmentJobsOutput struct {
	Body struct {
		Data       []EnrichmentJobResponse `json:"data"`
		Pagination PaginationMeta          `json:"pagination"`
	}
}

// EnrichmentJobSummaryRow is one (enricher, state) cell of the health matrix.
type EnrichmentJobSummaryRow struct {
	EnricherName string `json:"enricherName"`
	State        string `json:"state"`
	Count        int64  `json:"count"`
}

// EnrichmentJobsSummaryOutput is the response for GET /api/v1/enrichment-jobs/summary.
type EnrichmentJobsSummaryOutput struct {
	Body struct {
		Data []EnrichmentJobSummaryRow `json:"data"`
	}
}

// RetryEnrichmentJobInput is the request for POST /api/v1/admin/enrichment-jobs/{id}/retry.
type RetryEnrichmentJobInput struct {
	ID string `path:"id" doc:"Failed enrichment job UUID to reset back to 'queued'"`
}

// RetryAllFailedEnrichmentJobsInput is the request for POST /api/v1/admin/enrichment-jobs/retry-failed.
type RetryAllFailedEnrichmentJobsInput struct {
	EnricherName string `query:"enricher_name" enum:"user,oci-metadata,provenance" doc:"Limit the reset to a single enricher; omit to reset all"`
}

// RetryAllFailedEnrichmentJobsOutput is the response for POST /api/v1/admin/enrichment-jobs/retry-failed.
type RetryAllFailedEnrichmentJobsOutput struct {
	Body struct {
		Count int64 `json:"count" doc:"Number of rows transitioned from 'failed' to 'queued'"`
	}
}
