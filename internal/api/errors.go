package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/pfenerty/ocidex/internal/service"
)

// mapServiceError converts domain/service errors into huma status errors.
func mapServiceError(err error) error {
	var svcValErr *service.ValidationError
	if errors.As(err, &svcValErr) {
		return huma.Error400BadRequest(svcValErr.Message)
	}

	if errors.Is(err, service.ErrNotFound) {
		return huma.Error404NotFound("not found")
	}

	if errors.Is(err, service.ErrConflict) {
		return huma.Error409Conflict("conflict")
	}

	// A request that ran past router.go's middleware.Timeout arrives here with
	// the deadline error wrapped somewhere in the chain, and used to fall
	// through to the 500 below — which says the server broke when in fact the
	// query is simply too big for the ceiling. 504 says the true thing, and
	// keeps the slog.Error below meaning "nobody handled this", which is what
	// makes it worth alerting on.
	if errors.Is(err, context.DeadlineExceeded) {
		return huma.Error504GatewayTimeout("the query did not complete within the request deadline")
	}

	slog.Error("unhandled error", "err", err)
	return huma.Error500InternalServerError("internal error")
}

// parseUUID parses a string into a pgtype.UUID, returning a huma 400 error on failure.
func parseUUID(s string) (pgtype.UUID, error) {
	var id pgtype.UUID
	if err := id.Scan(s); err != nil {
		return pgtype.UUID{}, huma.Error400BadRequest(fmt.Sprintf("invalid UUID: %s", s))
	}
	if !id.Valid {
		return pgtype.UUID{}, huma.Error400BadRequest(fmt.Sprintf("invalid UUID: %s", s))
	}
	return id, nil
}
