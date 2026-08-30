package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/service"
)

// Member management (ocidex-y0hg.7). All three routes are guarded by
// RequireCapability(manage_member) with the namespace taken straight from the
// path, so these handlers do no authorization of their own — with one
// exception: which role the caller may hand out is a question about the
// caller's own grant rather than about the operation, and mayGrant answers it
// below.

// ListNamespaceMembers returns the namespace's members, owner first.
func (h *Handler) ListNamespaceMembers(ctx context.Context, in *ListNamespaceMembersInput) (*ListNamespaceMembersOutput, error) {
	members, err := h.namespaceService.ListMembers(ctx, in.ID)
	if err != nil {
		return nil, mapServiceError(err)
	}

	names := h.usernamesByID(ctx)
	out := &ListNamespaceMembersOutput{}
	out.Body.Data = make([]NamespaceMemberResponse, len(members))
	for i, m := range members {
		out.Body.Data[i] = toNamespaceMemberResponse(m, names[m.UserID])
	}
	return out, nil
}

// SetNamespaceMember grants a role, whether or not the user already holds one.
// The user must already exist: there is no invite flow, so a member is someone
// who has signed in at least once.
func (h *Handler) SetNamespaceMember(ctx context.Context, in *SetNamespaceMemberInput) (*SetNamespaceMemberOutput, error) {
	user, ok := UserFromContext(ctx)
	if !ok {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	if !mayGrant(user, in.ID, authz.Role(in.Body.Role)) {
		return nil, huma.Error403Forbidden("cannot grant a role you do not hold")
	}

	target, err := parseUUID(in.UserID)
	if err != nil {
		return nil, err
	}
	targetUser, err := h.authService.GetUser(ctx, target)
	if err != nil {
		return nil, huma.Error404NotFound("user not found")
	}

	member, err := h.namespaceService.SetMember(ctx, service.SetNamespaceMemberParams{
		NamespaceID: in.ID,
		UserID:      in.UserID,
		Role:        in.Body.Role,
	})
	if err != nil {
		return nil, mapServiceError(err)
	}
	return &SetNamespaceMemberOutput{
		Body: toNamespaceMemberResponse(member, targetUser.GitHubUsername),
	}, nil
}

// RemoveNamespaceMember removes a member. Removing the owner is a 409: a
// namespace with no owner is one nobody can administer.
func (h *Handler) RemoveNamespaceMember(ctx context.Context, in *RemoveNamespaceMemberInput) (*struct{}, error) {
	if err := h.namespaceService.RemoveMember(ctx, in.ID, in.UserID); err != nil {
		return nil, mapServiceError(err)
	}
	return nil, nil
}

// usernamesByID resolves user IDs to GitHub usernames for display. A failure to
// read the user list leaves the names blank rather than failing the request:
// the membership is the answer, and the username is decoration on it.
func (h *Handler) usernamesByID(ctx context.Context) map[string]string {
	names := map[string]string{}
	if h.authService == nil {
		return names
	}
	users, err := h.authService.ListUsers(ctx)
	if err != nil {
		return names
	}
	for _, u := range users {
		names[uuidToStr(u.ID)] = u.GitHubUsername
	}
	return names
}

func toNamespaceMemberResponse(m service.NamespaceMember, username string) NamespaceMemberResponse {
	caps := authz.Role(m.Role).Capabilities()
	out := NamespaceMemberResponse{
		UserID:    m.UserID,
		Username:  username,
		Role:      m.Role,
		Caps:      make([]string, len(caps)),
		CreatedAt: m.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	for i, c := range caps {
		out.Caps[i] = string(c)
	}
	return out
}
