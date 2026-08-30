package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// fakeNamespaceRepo answers the four membership queries from an in-memory
// roster keyed by user id, and records what the service asked it to write. The
// namespace-shaped methods are unused by member management and return zero
// values; a test that needed them would be testing the wrong seam.
type fakeNamespaceRepo struct {
	members map[string]string // user id -> role
	addErr  error

	added   *repository.AddNamespaceMemberParams
	removed *repository.RemoveNamespaceMemberParams
}

func (f *fakeNamespaceRepo) CreateNamespace(context.Context, repository.CreateNamespaceParams) (repository.CreateNamespaceRow, error) {
	return repository.CreateNamespaceRow{}, nil
}

func (f *fakeNamespaceRepo) GetNamespace(context.Context, pgtype.UUID) (repository.GetNamespaceRow, error) {
	return repository.GetNamespaceRow{}, nil
}

func (f *fakeNamespaceRepo) GetNamespaceByName(context.Context, string) (repository.GetNamespaceByNameRow, error) {
	return repository.GetNamespaceByNameRow{}, nil
}

func (f *fakeNamespaceRepo) ListNamespaces(context.Context, repository.ListNamespacesParams) ([]repository.ListNamespacesRow, error) {
	return nil, nil
}

func (f *fakeNamespaceRepo) UpdateNamespace(context.Context, repository.UpdateNamespaceParams) (repository.UpdateNamespaceRow, error) {
	return repository.UpdateNamespaceRow{}, nil
}

func (f *fakeNamespaceRepo) DeleteNamespace(context.Context, pgtype.UUID) (int64, error) {
	return 1, nil
}

func (f *fakeNamespaceRepo) AddNamespaceMember(_ context.Context, arg repository.AddNamespaceMemberParams) (repository.NamespaceMember, error) {
	f.added = &arg
	if f.addErr != nil {
		return repository.NamespaceMember{}, f.addErr
	}
	return repository.NamespaceMember{
		NamespaceID: arg.NamespaceID,
		UserID:      arg.UserID,
		Role:        arg.Role,
	}, nil
}

func (f *fakeNamespaceRepo) GetNamespaceMember(_ context.Context, arg repository.GetNamespaceMemberParams) (repository.NamespaceMember, error) {
	role, ok := f.members[uuidToStr(arg.UserID)]
	if !ok {
		return repository.NamespaceMember{}, pgx.ErrNoRows
	}
	return repository.NamespaceMember{
		NamespaceID: arg.NamespaceID,
		UserID:      arg.UserID,
		Role:        role,
	}, nil
}

func (f *fakeNamespaceRepo) ListNamespaceMembers(_ context.Context, namespaceID pgtype.UUID) ([]repository.NamespaceMember, error) {
	out := make([]repository.NamespaceMember, 0, len(f.members))
	for id, role := range f.members {
		uid, err := parseUUID(id)
		if err != nil {
			return nil, err
		}
		out = append(out, repository.NamespaceMember{NamespaceID: namespaceID, UserID: uid, Role: role})
	}
	return out, nil
}

func (f *fakeNamespaceRepo) RemoveNamespaceMember(_ context.Context, arg repository.RemoveNamespaceMemberParams) (int64, error) {
	f.removed = &arg
	if _, ok := f.members[uuidToStr(arg.UserID)]; !ok {
		return 0, nil
	}
	return 1, nil
}

const (
	memberTestNamespace = "11111111-1111-1111-1111-111111111111"
	memberTestOwner     = "22222222-2222-2222-2222-222222222222"
	memberTestOther     = "33333333-3333-3333-3333-333333333333"
)

func memberService(members map[string]string) (*namespaceService, *fakeNamespaceRepo) {
	repo := &fakeNamespaceRepo{members: members}
	return &namespaceService{repo: repo}, repo
}

// TestSetMemberAddsAndChangesRoles covers the two things a PUT means: a user
// with no seat gets one, and a user with one gets a different one.
func TestSetMemberAddsAndChangesRoles(t *testing.T) {
	is := is.New(t)
	svc, repo := memberService(map[string]string{memberTestOwner: "owner"})

	added, err := svc.SetMember(context.Background(), SetNamespaceMemberParams{
		NamespaceID: memberTestNamespace,
		UserID:      memberTestOther,
		Role:        "security",
	})
	is.NoErr(err)
	is.Equal(added.Role, "security")
	is.Equal(added.UserID, memberTestOther)
	is.Equal(repo.added.Role, "security")

	repo.members[memberTestOther] = "security"
	changed, err := svc.SetMember(context.Background(), SetNamespaceMemberParams{
		NamespaceID: memberTestNamespace,
		UserID:      memberTestOther,
		Role:        "viewer",
	})
	is.NoErr(err)
	is.Equal(changed.Role, "viewer")
}

// TestSetMemberRejectsUnknownRole keeps the closed role set closed at the
// service boundary. The database CHECK is the backstop, not the message.
func TestSetMemberRejectsUnknownRole(t *testing.T) {
	is := is.New(t)
	svc, repo := memberService(nil)

	_, err := svc.SetMember(context.Background(), SetNamespaceMemberParams{
		NamespaceID: memberTestNamespace,
		UserID:      memberTestOther,
		Role:        "superuser",
	})
	var valErr *ValidationError
	is.True(errors.As(err, &valErr))
	is.Equal(repo.added, (*repository.AddNamespaceMemberParams)(nil)) // never reached the write
}

// TestSetMemberRefusesToDemoteTheOwner is the guard namespace_one_owner cannot
// provide: the index tolerates zero owners as readily as one, so demoting the
// only owner would leave a namespace nobody can administer and no constraint
// would notice.
func TestSetMemberRefusesToDemoteTheOwner(t *testing.T) {
	is := is.New(t)
	svc, repo := memberService(map[string]string{memberTestOwner: "owner"})

	_, err := svc.SetMember(context.Background(), SetNamespaceMemberParams{
		NamespaceID: memberTestNamespace,
		UserID:      memberTestOwner,
		Role:        "maintainer",
	})
	is.True(errors.Is(err, ErrConflict))
	is.Equal(repo.added, (*repository.AddNamespaceMemberParams)(nil))
}

// TestSetMemberOwnerToOwnerIsNotADemote pins the boundary of the rule above: a
// PUT that restates the owner's own role is a no-op, not a conflict.
func TestSetMemberOwnerToOwnerIsNotADemote(t *testing.T) {
	is := is.New(t)
	svc, _ := memberService(map[string]string{memberTestOwner: "owner"})

	m, err := svc.SetMember(context.Background(), SetNamespaceMemberParams{
		NamespaceID: memberTestNamespace,
		UserID:      memberTestOwner,
		Role:        "owner",
	})
	is.NoErr(err)
	is.Equal(m.Role, "owner")
}

// TestSetMemberSecondOwnerIsAConflict is the other half: the unique violation
// namespace_one_owner raises becomes a 409 rather than a 500. The service does
// not pre-read to find this, deliberately — a SELECT-then-INSERT would race a
// concurrent grant.
func TestSetMemberSecondOwnerIsAConflict(t *testing.T) {
	is := is.New(t)
	svc, repo := memberService(map[string]string{memberTestOwner: "owner"})
	repo.addErr = &pgconn.PgError{Code: "23505", ConstraintName: "namespace_one_owner"}

	_, err := svc.SetMember(context.Background(), SetNamespaceMemberParams{
		NamespaceID: memberTestNamespace,
		UserID:      memberTestOther,
		Role:        "owner",
	})
	is.True(errors.Is(err, ErrConflict))
}

// TestRemoveMember covers the ordinary case and the two refusals: the owner's
// seat cannot be vacated, and a user who holds no seat is a 404 rather than a
// silent success.
func TestRemoveMember(t *testing.T) {
	is := is.New(t)
	svc, repo := memberService(map[string]string{
		memberTestOwner: "owner",
		memberTestOther: "developer",
	})

	is.NoErr(svc.RemoveMember(context.Background(), memberTestNamespace, memberTestOther))
	is.Equal(uuidToStr(repo.removed.UserID), memberTestOther)

	err := svc.RemoveMember(context.Background(), memberTestNamespace, memberTestOwner)
	is.True(errors.Is(err, ErrConflict))

	delete(repo.members, memberTestOther)
	err = svc.RemoveMember(context.Background(), memberTestNamespace, memberTestOther)
	is.True(errors.Is(err, ErrNotFound))
}

// TestListMembers projects the repository rows without reinterpreting them.
func TestListMembers(t *testing.T) {
	is := is.New(t)
	svc, _ := memberService(map[string]string{memberTestOwner: "owner"})

	members, err := svc.ListMembers(context.Background(), memberTestNamespace)
	is.NoErr(err)
	is.Equal(len(members), 1)
	is.Equal(members[0].UserID, memberTestOwner)
	is.Equal(members[0].Role, "owner")
	is.Equal(members[0].NamespaceID, memberTestNamespace)
}

// TestMemberOperationsRejectMalformedIDs keeps a bad path param a 404 rather
// than a database round trip.
func TestMemberOperationsRejectMalformedIDs(t *testing.T) {
	is := is.New(t)
	svc, _ := memberService(nil)

	_, err := svc.ListMembers(context.Background(), "not-a-uuid")
	is.True(errors.Is(err, ErrNotFound))

	_, err = svc.SetMember(context.Background(), SetNamespaceMemberParams{
		NamespaceID: memberTestNamespace, UserID: "not-a-uuid", Role: "viewer",
	})
	is.True(errors.Is(err, ErrNotFound))

	is.True(errors.Is(svc.RemoveMember(context.Background(), "not-a-uuid", memberTestOther), ErrNotFound))
}
