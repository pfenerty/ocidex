package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"

	"github.com/pfenerty/ocidex/internal/service"
	"github.com/pfenerty/ocidex/internal/uuidx"
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

	if errors.Is(err, service.ErrConflict) || errors.Is(err, service.ErrNamespaceExists) {
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

// requireUUID checks that a request's ID is a UUID, answering 400 when it
// isn't, and returns it in canonical form. IDs cross into the services as
// strings (ocidex-8xij.4); checking here keeps a malformed one a 400 whatever
// the handler does with service errors.
func requireUUID(s string) (string, error) {
	id, err := uuidx.Parse(s)
	if err != nil {
		return "", huma.Error400BadRequest(fmt.Sprintf("invalid UUID: %s", s))
	}
	return id.String(), nil
}
