package api

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/service"
)

// lookupConflictResponses declares the 409 body on a resolver operation. huma
// only infers response schemas from the handler's output struct, and the
// conflict travels as an error, so without this the candidate list would be
// absent from web/openapi.json and therefore from the generated TypeScript
// client.
func lookupConflictResponses(api huma.API) map[string]*huma.Response {
	schema := api.OpenAPI().Components.Schemas.Schema(reflect.TypeOf(LookupConflictError{}), true, "LookupConflict")
	return map[string]*huma.Response{
		"409": {
			Description: "More than one visible candidate matched; narrow the query with additional qualifiers.",
			Content: map[string]*huma.MediaType{
				"application/json": {Schema: schema},
			},
		},
	}
}

// LookupConflictError is the 409 body an ADR-042 name-keyed resolver returns when
// more than one *visible* candidate matches. 409 is used rather than 300
// Multiple Choices because huma models a typed error body, so Candidates
// survives into the generated OpenAPI and TypeScript client; a 300 does not.
type LookupConflictError struct {
	Status     int                       `json:"status" doc:"HTTP status code"`
	Title      string                    `json:"title" doc:"Short, human-readable summary"`
	Detail     string                    `json:"detail" doc:"Explanation of the ambiguity"`
	Candidates []service.LookupCandidate `json:"candidates" doc:"Matching resources; retry one rung further down the qualifier ladder to select one"`
}

// Error implements error so a *LookupConflictError can be returned from a handler.
func (e *LookupConflictError) Error() string { return e.Detail }

// GetStatus implements huma.StatusError, which is what makes huma serialize
// this value as-is instead of wrapping it in the default huma.ErrorModel.
func (e *LookupConflictError) GetStatus() int { return e.Status }

// newLookupConflict builds the 409 for a resolver whose query matched more
// than one visible candidate.
func newLookupConflict(resource string, candidates []service.LookupCandidate) *LookupConflictError {
	return &LookupConflictError{
		Status:     http.StatusConflict,
		Title:      "Ambiguous lookup",
		Detail:     fmt.Sprintf("%d visible %s candidates match; narrow the query with additional qualifiers", len(candidates), resource),
		Candidates: candidates,
	}
}

// LookupArtifact handles GET /api/v1/artifacts/lookup.
//
// It resolves the ADR-042 R4 qualifier ladder (name -> +type -> +group) to a
// single artifact and returns the same body as GET /api/v1/artifacts/{id}:
// 200 on exactly one visible candidate, 404 on none, 409 on more than one.
// A private artifact collapses to 404 rather than 403 (R5), matching
// GetRegistryByName's not-found rule.
func (h *Handler) LookupArtifact(ctx context.Context, input *LookupArtifactInput) (*GetArtifactOutput, error) {
	vis := visibilityFilterFromContext(ctx)

	candidates, err := h.searchService.LookupArtifact(ctx, service.ArtifactLookupQuery{
		Name:  input.Name,
		Type:  input.Type,
		Group: input.Group,
	}, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	switch {
	case len(candidates) == 0:
		return nil, huma.Error404NotFound("artifact not found")
	case len(candidates) > 1:
		return nil, newLookupConflict("artifact", candidates)
	}

	id, err := parseUUID(candidates[0].ID)
	if err != nil {
		return nil, err
	}
	detail, err := h.searchService.GetArtifact(ctx, id, vis)
	if err != nil {
		return nil, mapServiceError(err)
	}

	out := &GetArtifactOutput{}
	out.Body = detail
	return out, nil
}
