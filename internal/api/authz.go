package api

import (
	"context"

	"github.com/pfenerty/ocidex/internal/service"
)

// visibilityFilterFromContext builds the row-visibility filter for the caller
// in ctx. It is the only place in the API layer that constructs a
// service.VisibilityFilter: the filter is the row-level half of the
// authorization model (the middlewares in middleware.go are the operation-level
// half), and a hand-rolled second copy that forgets IsAdmin — or, worse,
// forgets to narrow at all for an unauthenticated caller — is exactly how a
// visibility bug ships.
//
// An unauthenticated caller gets the zero filter, which selects public data
// only. That is deliberate: a public-class operation answers anonymous callers
// with a narrower result set rather than a 403 (see docs/AUTH_MATRIX.md), so
// "no user" must be a valid, safe filter rather than an error.
func visibilityFilterFromContext(ctx context.Context) service.VisibilityFilter {
	user, ok := UserFromContext(ctx)
	if !ok {
		return service.VisibilityFilter{}
	}
	return service.VisibilityFilter{
		IsAdmin: user.Role == roleAdmin,
		UserID:  user.ID,
	}
}

// ownedFilterFromContext builds the filter for the /api/v1/users/me/*
// collections: the rows the caller owns, and nothing else.
//
// It is deliberately not visibilityFilterFromContext with a flag flipped at the
// call site. The two differ in a way that is easy to get backwards — the
// visibility filter includes namespaces someone else made public, which a
// "mine" collection must exclude — and IsAdmin is left false because an admin
// asking for their own namespaces means their own, not the installation's.
//
// An unauthenticated caller yields the zero filter with OwnedOnly set, which
// matches no rows. Every route using this is authenticated-class anyway, so
// that path is a backstop rather than a supported case.
func ownedFilterFromContext(ctx context.Context) service.VisibilityFilter {
	user, ok := UserFromContext(ctx)
	if !ok {
		return service.VisibilityFilter{OwnedOnly: true}
	}
	return service.VisibilityFilter{UserID: user.ID, OwnedOnly: true}
}
