package api

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/service"
)

// ListEnrichmentJobs returns a paginated, optionally filtered list of enrichment jobs.
func (h *Handler) ListEnrichmentJobs(ctx context.Context, in *ListEnrichmentJobsInput) (*ListEnrichmentJobsOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	jobs, total, err := h.enrichJobService.List(ctx, in.State, in.EnricherName, in.Limit, in.Offset)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing enrichment jobs: %v", err))
	}
	out := &ListEnrichmentJobsOutput{}
	out.Body.Data = make([]EnrichmentJobResponse, len(jobs))
	for i, j := range jobs {
		out.Body.Data[i] = toEnrichmentJobResponse(j)
	}
	out.Body.Pagination = PaginationMeta{
		Total:  total,
		Limit:  in.Limit,
		Offset: in.Offset,
	}
	return out, nil
}

// EnrichmentJobsSummary returns per-(enricher, state) counts for the health matrix.
func (h *Handler) EnrichmentJobsSummary(ctx context.Context, _ *struct{}) (*EnrichmentJobsSummaryOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	rows, err := h.enrichJobService.Summary(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("summarizing enrichment jobs: %v", err))
	}
	out := &EnrichmentJobsSummaryOutput{}
	out.Body.Data = make([]EnrichmentJobSummaryRow, len(rows))
	for i, r := range rows {
		out.Body.Data[i] = EnrichmentJobSummaryRow{EnricherName: r.EnricherName, State: r.State, Count: r.Count}
	}
	return out, nil
}

// RetryEnrichmentJob resets a 'failed' enrichment_jobs row back to 'queued'. Admin-only.
func (h *Handler) RetryEnrichmentJob(ctx context.Context, in *RetryEnrichmentJobInput) (*struct{}, error) {
	if err := requireAdminWrite(ctx); err != nil {
		return nil, err
	}
	if err := h.enrichJobService.Retry(ctx, in.ID); err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("retry enrichment job: %v", err))
	}
	return nil, nil
}

// RetryAllFailedEnrichmentJobs resets every 'failed' enrichment_jobs row back to
// 'queued', optionally scoped to one enricher. Returns the count. Admin-only.
func (h *Handler) RetryAllFailedEnrichmentJobs(ctx context.Context, in *RetryAllFailedEnrichmentJobsInput) (*RetryAllFailedEnrichmentJobsOutput, error) {
	if err := requireAdminWrite(ctx); err != nil {
		return nil, err
	}
	n, err := h.enrichJobService.RetryAllFailed(ctx, in.EnricherName)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("retry all failed: %v", err))
	}
	out := &RetryAllFailedEnrichmentJobsOutput{}
	out.Body.Count = n
	return out, nil
}

// requireAdminWrite enforces an authenticated admin with write access, mirroring
// the guard used by the scan-job retry handlers.
func requireAdminWrite(ctx context.Context) error {
	user, ok := UserFromContext(ctx)
	if !ok {
		return huma.Error401Unauthorized("not authenticated")
	}
	if user.Role != roleAdmin {
		return huma.Error403Forbidden("admin only")
	}
	if !isWriteAllowed(user) {
		return huma.Error403Forbidden("read-only API key cannot perform write operations")
	}
	return nil
}

func toEnrichmentJobResponse(j service.EnrichJob) EnrichmentJobResponse {
	r := EnrichmentJobResponse{
		ID:           j.ID,
		SbomID:       j.SbomID,
		EnricherName: j.EnricherName,
		State:        j.State,
		Attempts:     j.Attempts,
		LastError:    j.LastError,
		WorkerID:     j.WorkerID,
		SbomDigest:   j.SbomDigest,
		ArtifactName: j.ArtifactName,
		CreatedAt:    j.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if j.StartedAt != nil {
		s := j.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
		r.StartedAt = &s
	}
	if j.LastAttemptAt != nil {
		s := j.LastAttemptAt.UTC().Format("2006-01-02T15:04:05Z")
		r.LastAttemptAt = &s
	}
	if j.FinishedAt != nil {
		s := j.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
		r.FinishedAt = &s
	}
	return r
}
