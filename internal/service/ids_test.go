package service

import (
	"context"
	"errors"
	"testing"

	"github.com/matryer/is"
)

// Services take IDs as strings (ocidex-8xij.4). A malformed one is the
// caller's mistake, reported as a ValidationError before any query runs, so
// the API answers 400 rather than 404 or 500.
func TestMalformedIDIsAValidationError(t *testing.T) {
	ctx := context.Background()
	search := &searchService{} // no database: the ID must be rejected first
	sboms := &sbomService{}
	auth := &authService{}
	calls := map[string]func() error{
		"GetSBOM": func() error { _, err := search.GetSBOM(ctx, "nope", false, VisibilityFilter{}); return err },
		"GetArtifact": func() error {
			_, err := search.GetArtifact(ctx, "nope", VisibilityFilter{})
			return err
		},
		"DiffSBOMs (second ID)": func() error {
			_, err := search.DiffSBOMs(ctx, "3e671687-395b-41f5-a30f-a58921a69b79", "nope", VisibilityFilter{})
			return err
		},
		"GetSBOMNamespaceID": func() error { _, err := sboms.GetSBOMNamespaceID(ctx, "nope"); return err },
		"DeleteArtifactFromNamespaces": func() error {
			return sboms.DeleteArtifactFromNamespaces(ctx, "3e671687-395b-41f5-a30f-a58921a69b79", []string{"nope"})
		},
		"ListAPIKeys": func() error { _, err := auth.ListAPIKeys(ctx, "nope"); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			is := is.New(t)
			var verr *ValidationError
			is.True(errors.As(call(), &verr))
			is.Equal(verr.Message, "invalid UUID: nope")
		})
	}
}
