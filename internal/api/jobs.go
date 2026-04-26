package api

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/service"
)

// ListScanJobs returns a paginated, optionally filtered list of scan jobs.
func (h *Handler) ListScanJobs(ctx context.Context, in *ListScanJobsInput) (*ListScanJobsOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	jobs, total, err := h.jobService.List(ctx, in.State, in.Limit, in.Offset)
	if err != nil {
		return nil, huma.Error500InternalServerError(fmt.Sprintf("listing jobs: %v", err))
	}
	out := &ListScanJobsOutput{}
	out.Body.Data = make([]ScanJobResponse, len(jobs))
	for i, j := range jobs {
		out.Body.Data[i] = toScanJobResponse(j)
	}
	out.Body.Pagination = PaginationMeta{
		Total:  total,
		Limit:  in.Limit,
		Offset: in.Offset,
	}
	return out, nil
}

// GetScanJob returns a single scan job by UUID.
func (h *Handler) GetScanJob(ctx context.Context, in *GetScanJobInput) (*GetScanJobOutput, error) {
	if _, ok := UserFromContext(ctx); !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	job, err := h.jobService.Get(ctx, in.ID)
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &GetScanJobOutput{Body: toScanJobResponse(job)}, nil
}

func toScanJobResponse(j service.ScanJob) ScanJobResponse {
	r := ScanJobResponse{
		ID:         j.ID,
		RegistryID: j.RegistryID,
		Repository: j.Repository,
		Digest:     j.Digest,
		Tag:        j.Tag,
		State:      string(j.State),
		Attempts:   j.Attempts,
		LastError:  j.LastError,
		NATSMsgID:  j.NATSMsgID,
		SbomID:     j.SbomID,
		CreatedAt:  j.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if j.StartedAt != nil {
		s := j.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
		r.StartedAt = &s
	}
	if j.FinishedAt != nil {
		s := j.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
		r.FinishedAt = &s
	}
	return r
}
