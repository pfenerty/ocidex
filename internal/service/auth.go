package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pfenerty/ocidex/internal/auth"
	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/repository"
)

// AuthUser is the authenticated principal attached to a request context.
type AuthUser struct {
	ID pgtype.UUID
	// DisplayName is what to call this person in the UI. It is deliberately not
	// an identifier: it comes from whichever issuer last signed them in, and two
	// accounts may carry the same one.
	DisplayName string
	Role        string
	// APIKeyAuth reports whether this request was authenticated by an API key
	// rather than by a session cookie.
	APIKeyAuth bool
	// APIKeyCaps is the capability ceiling declared on that key. It is only
	// ever a ceiling: what the caller may actually do is this set INTERSECTED
	// with their live namespace roles, which is what makes a demotion narrow
	// every key the member holds without a rotation.
	//
	// Meaningless unless APIKeyAuth — a session is the user themselves and
	// carries no ceiling, and an empty slice on a key means a key that may do
	// nothing but read public data.
	APIKeyCaps []authz.Capability
	// Grants is the caller's namespace membership, keyed by namespace ID
	// string. A namespace absent from the map is one the caller is not a member
	// of, which grants nothing — a public namespace is readable through the SQL
	// visibility functions, not through here.
	//
	// It is resolved per request (LoadGrants, called once from the API layer's
	// authenticate middleware) and deliberately not stored on the session or
	// API-key row. The epic's acceptance criterion is that a role change takes
	// effect without a re-login, and a grant set cached at login is precisely
	// how that criterion gets broken by accident.
	Grants map[string]authz.Role
}

// APIKeyMeta is the display-safe representation of an API key (no hash).
type APIKeyMeta struct {
	ID           pgtype.UUID
	Name         string
	Prefix       string
	Capabilities []authz.Capability
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// KeyAllows reports whether the credential this request arrived on permits c at
// all, before any namespace membership is consulted.
//
// A session always does: the ceiling exists to make a key narrower than its
// owner, and a browser session is the owner. This is the "INTERSECT" half of
// the key model and is deliberately separate from authz.Allow, which knows
// about roles and not about credentials — including for an installation admin,
// whose admin short-circuit must not out-rank a key they deliberately issued
// read-only.
func (u AuthUser) KeyAllows(c authz.Capability) bool {
	if !u.APIKeyAuth {
		return true
	}
	for _, held := range u.APIKeyCaps {
		if held == c {
			return true
		}
	}
	return false
}

// KeyAllowsAnyWrite reports whether the credential permits any state-mutating
// capability. It is what RequireWrite asks, and the reason the old read /
// read-write pair can retire without touching the ~40 operations that declare
// Write.
func (u AuthUser) KeyAllowsAnyWrite() bool {
	if !u.APIKeyAuth {
		return true
	}
	for _, held := range u.APIKeyCaps {
		if held.Mutating() {
			return true
		}
	}
	return false
}

// AuthService handles interactive sign-in, sessions, and API key management.
type AuthService interface {
	// ProviderNames lists the configured issuers, sorted, for a caller that has
	// to offer a choice.
	ProviderNames() []string
	// BuildAuthURL is where to send the browser to sign in through provider.
	// verifier is the PKCE code verifier for this attempt; providers that do
	// not use PKCE ignore it.
	BuildAuthURL(provider, state, verifier string) (string, error)
	// ExchangeCodeForUser redeems a callback code against provider and resolves
	// it to the account that identity belongs to, creating one on first sign-in.
	ExchangeCodeForUser(ctx context.Context, provider, code, verifier string) (AuthUser, error)
	CreateSession(ctx context.Context, userID pgtype.UUID) (plaintext string, err error)
	ValidateSession(ctx context.Context, token string) (AuthUser, error)
	DeleteSession(ctx context.Context, token string) error
	CreateAPIKey(ctx context.Context, userID pgtype.UUID, name string, caps []authz.Capability) (plaintext string, err error)
	ValidateAPIKey(ctx context.Context, rawKey string) (AuthUser, error)
	ListAPIKeys(ctx context.Context, userID pgtype.UUID) ([]APIKeyMeta, error)
	DeleteAPIKey(ctx context.Context, userID pgtype.UUID, keyID pgtype.UUID) error
	GetUser(ctx context.Context, userID pgtype.UUID) (AuthUser, error)
	ListUsers(ctx context.Context) ([]AuthUser, error)
	UpdateUserRole(ctx context.Context, targetID pgtype.UUID, role string) (AuthUser, error)
	CleanExpiredSessions(ctx context.Context) error
	// LoadGrants returns the user's namespace memberships keyed by namespace ID.
	// The API layer calls it once per authenticated request; see AuthUser.Grants
	// for why it is not folded into ValidateSession's row.
	LoadGrants(ctx context.Context, userID pgtype.UUID) (map[string]authz.Role, error)
}

type authService struct {
	pool *pgxpool.Pool
	repo repository.AuthRepository
	// providers is keyed by Provider.Name. The service never names an issuer
	// itself: which one a sign-in uses arrives from the caller, and an unknown
	// name is an error rather than a silent fallback to GitHub.
	providers map[string]auth.Provider
	cfg       *config.Config
	publisher event.Publisher
}

// NewAuthService constructs an AuthService over the given identity providers,
// keyed by name.
func NewAuthService(pool *pgxpool.Pool, cfg *config.Config, publisher event.Publisher, providers []auth.Provider) AuthService {
	byName := make(map[string]auth.Provider, len(providers))
	for _, p := range providers {
		byName[p.Name()] = p
	}
	return &authService{
		pool:      pool,
		repo:      repository.New(pool),
		providers: byName,
		cfg:       cfg,
		publisher: publisher,
	}
}

// displayName reads ocidex_user.display_name, which is nullable because the
// column arrived in migration 00069 with nothing to seed it from for a row that
// had no github_username. An account with no name renders as empty rather than
// failing the request.
func displayName(v pgtype.Text) string { return v.String }

func (s *authService) ProviderNames() []string {
	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *authService) BuildAuthURL(provider, state, verifier string) (string, error) {
	p, ok := s.providers[provider]
	if !ok {
		return "", &ValidationError{Message: fmt.Sprintf("unknown identity provider %q", provider)}
	}
	return p.AuthURL(state, verifier), nil
}

func (s *authService) ExchangeCodeForUser(ctx context.Context, provider, code, verifier string) (AuthUser, error) {
	p, ok := s.providers[provider]
	if !ok {
		return AuthUser{}, &ValidationError{Message: fmt.Sprintf("unknown identity provider %q", provider)}
	}
	id, err := p.Exchange(ctx, code, verifier)
	if err != nil {
		return AuthUser{}, fmt.Errorf("exchanging code with %s: %w", provider, err)
	}
	if id.Subject == "" {
		return AuthUser{}, fmt.Errorf("%s returned an identity with no subject", provider)
	}
	return s.resolveIdentity(ctx, id)
}

// resolveIdentity maps an Identity onto the account that holds it, creating the
// account on first sign-in.
//
// The match is on (provider, subject) and nothing else. Matching on email
// instead — "this address already has an account, so it must be the same
// person" — would let any issuer that does not verify addresses take over an
// account on another issuer, so the address is stored and never compared.
func (s *authService) resolveIdentity(ctx context.Context, id auth.Identity) (AuthUser, error) {
	u, err := s.repo.GetUserByIdentity(ctx, repository.GetUserByIdentityParams{
		Provider: id.Provider,
		Subject:  id.Subject,
	})
	switch {
	case err == nil:
		if err := s.repo.UpsertIdentityEmail(ctx, repository.UpsertIdentityEmailParams{
			Provider: id.Provider,
			Subject:  id.Subject,
			Email:    id.Email,
		}); err != nil {
			return AuthUser{}, fmt.Errorf("updating identity email: %w", err)
		}
		u, err = s.repo.TouchUserProfile(ctx, repository.TouchUserProfileParams{
			ID:          u.ID,
			DisplayName: id.DisplayName,
			Email:       id.Email,
		})
		if err != nil {
			return AuthUser{}, fmt.Errorf("updating user profile: %w", err)
		}
		return AuthUser{ID: u.ID, DisplayName: displayName(u.DisplayName), Role: u.Role}, nil

	case errors.Is(err, pgx.ErrNoRows):
		row, createErr := s.repo.CreateUserWithIdentity(ctx, newUserParams(id))
		if createErr == nil {
			return AuthUser{ID: row.ID, DisplayName: displayName(row.DisplayName), Role: row.Role}, nil
		}
		// Two tabs can finish a first sign-in at the same time; the loser hits
		// user_identity's UNIQUE (provider, subject). The account it wanted now
		// exists, so look it up rather than failing a legitimate login.
		u, lookupErr := s.repo.GetUserByIdentity(ctx, repository.GetUserByIdentityParams{
			Provider: id.Provider,
			Subject:  id.Subject,
		})
		if lookupErr != nil {
			return AuthUser{}, fmt.Errorf("creating user: %w", createErr)
		}
		return AuthUser{ID: u.ID, DisplayName: displayName(u.DisplayName), Role: u.Role}, nil

	default:
		return AuthUser{}, fmt.Errorf("looking up identity: %w", err)
	}
}

// newUserParams shapes the insert for a brand-new account.
//
// The GitHub columns are still written for the GitHub provider and left NULL
// for every other one. They are dead weight above the repository — nothing
// reads them any more — but migration 00069 keeps them for one release so a
// rollback finds accounts created in the meantime. Delete this special case
// with the columns in ocidex-iqkt.5.
func newUserParams(id auth.Identity) repository.CreateUserWithIdentityParams {
	p := repository.CreateUserWithIdentityParams{
		Provider:    id.Provider,
		Subject:     id.Subject,
		DisplayName: pgtype.Text{String: id.DisplayName, Valid: id.DisplayName != ""},
		Email:       pgtype.Text{String: id.Email, Valid: id.Email != ""},
	}
	if id.Provider == auth.ProviderGitHub {
		if n, err := strconv.ParseInt(id.Subject, 10, 64); err == nil {
			p.GithubID = pgtype.Int8{Int64: n, Valid: true}
		}
		p.GithubUsername = pgtype.Text{String: id.DisplayName, Valid: id.DisplayName != ""}
	}
	return p
}

func (s *authService) CreateSession(ctx context.Context, userID pgtype.UUID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating session token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256hex(plaintext)

	expiry := time.Now().Add(time.Duration(s.cfg.SessionMaxAgeDays) * 24 * time.Hour)
	_, err := s.repo.CreateSession(ctx, repository.CreateSessionParams{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: pgtype.Timestamptz{Time: expiry, Valid: true},
	})
	if err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}
	s.publisher.Publish(ctx, event.UserLoggedIn, event.UserLoggedInData{UserID: userID})
	return plaintext, nil
}

func (s *authService) ValidateSession(ctx context.Context, token string) (AuthUser, error) {
	row, err := s.repo.GetSessionByTokenHash(ctx, sha256hex(token))
	if err != nil {
		return AuthUser{}, fmt.Errorf("session not found: %w", err)
	}
	return AuthUser{
		ID:          row.UserID,
		DisplayName: displayName(row.DisplayName),
		Role:        row.Role,
	}, nil
}

func (s *authService) DeleteSession(ctx context.Context, token string) error {
	// Look up user before deleting so we can attribute the logout event.
	user, userErr := s.ValidateSession(ctx, token)
	if err := s.repo.DeleteSession(ctx, sha256hex(token)); err != nil {
		return err
	}
	if userErr == nil {
		s.publisher.Publish(ctx, event.UserLoggedOut, event.UserLoggedOutData{UserID: user.ID})
	}
	return nil
}

// CreateAPIKey mints a key with the given capability ceiling.
//
// An empty ceiling means "everything I can do", which is both the historical
// read-write behaviour and the right default: the narrowing that matters
// happens at validation time against live membership, so a key that names no
// capability is a key that simply tracks its owner. A caller who wants a
// narrow key says so explicitly.
func (s *authService) CreateAPIKey(ctx context.Context, userID pgtype.UUID, name string, caps []authz.Capability) (string, error) {
	if len(caps) == 0 {
		caps = authz.AllCapabilities()
	}
	for _, c := range caps {
		if !c.Valid() {
			return "", &ValidationError{Message: fmt.Sprintf("unknown capability %q", c)}
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating api key: %w", err)
	}
	plaintext := "ocidex_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256hex(plaintext)
	prefix := plaintext
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}

	_, err := s.repo.CreateAPIKey(ctx, repository.CreateAPIKeyParams{
		UserID:  userID,
		Name:    name,
		KeyHash: hash,
		Prefix:  prefix,

		Capabilities: authz.Strings(caps),
	})
	if err != nil {
		return "", fmt.Errorf("creating api key: %w", err)
	}
	return plaintext, nil
}

func (s *authService) ValidateAPIKey(ctx context.Context, rawKey string) (AuthUser, error) {
	row, err := s.repo.GetAPIKeyByHash(ctx, sha256hex(rawKey))
	if err != nil {
		return AuthUser{}, fmt.Errorf("api key not found: %w", err)
	}
	go func() { //nolint:gosec
		if err := s.repo.TouchAPIKeyLastUsed(context.Background(), row.ID); err != nil {
			slog.Warn("touch api key last used", "err", err)
		}
	}()
	// An unknown capability string on the row is dropped rather than rejected:
	// it can only come from a version that knew about a capability this build
	// does not, and a key must narrow — never fail open — across a downgrade.
	caps := make([]authz.Capability, 0, len(row.Capabilities))
	for _, name := range row.Capabilities {
		if c := authz.Capability(name); c.Valid() {
			caps = append(caps, c)
		}
	}
	return AuthUser{
		ID:          row.UserID,
		DisplayName: displayName(row.DisplayName),
		Role:        row.Role,
		APIKeyAuth:  true,
		APIKeyCaps:  caps,
	}, nil
}

func (s *authService) ListAPIKeys(ctx context.Context, userID pgtype.UUID) ([]APIKeyMeta, error) {
	rows, err := s.repo.ListAPIKeysByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing api keys: %w", err)
	}
	out := make([]APIKeyMeta, len(rows))
	for i, r := range rows {
		caps, err := authz.ParseCapabilities(r.Capabilities)
		if err != nil {
			// Same reasoning as ValidateAPIKey: render what this build
			// understands rather than failing the whole listing.
			caps = nil
			for _, name := range r.Capabilities {
				if c := authz.Capability(name); c.Valid() {
					caps = append(caps, c)
				}
			}
		}
		m := APIKeyMeta{
			ID:           r.ID,
			Name:         r.Name,
			Prefix:       r.Prefix,
			Capabilities: caps,
			CreatedAt:    r.CreatedAt.Time,
		}
		if r.LastUsedAt.Valid {
			t := r.LastUsedAt.Time
			m.LastUsedAt = &t
		}
		out[i] = m
	}
	return out, nil
}

func (s *authService) DeleteAPIKey(ctx context.Context, userID pgtype.UUID, keyID pgtype.UUID) error {
	n, err := s.repo.DeleteAPIKey(ctx, repository.DeleteAPIKeyParams{
		ID:     keyID,
		UserID: userID,
	})
	if err != nil {
		return fmt.Errorf("deleting api key: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (s *authService) GetUser(ctx context.Context, userID pgtype.UUID) (AuthUser, error) {
	u, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return AuthUser{}, fmt.Errorf("getting user: %w", err)
	}
	return AuthUser{
		ID:          u.ID,
		DisplayName: displayName(u.DisplayName),
		Role:        u.Role,
	}, nil
}

func (s *authService) ListUsers(ctx context.Context) ([]AuthUser, error) {
	users, err := s.repo.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	out := make([]AuthUser, len(users))
	for i, u := range users {
		out[i] = AuthUser{
			ID:          u.ID,
			DisplayName: displayName(u.DisplayName),
			Role:        u.Role,
		}
	}
	return out, nil
}

// User roles — the values stored in users.role.
const (
	roleAdmin  = "admin"
	roleMember = "member"
	roleViewer = "viewer"
)

func (s *authService) UpdateUserRole(ctx context.Context, targetID pgtype.UUID, role string) (AuthUser, error) {
	switch role {
	case roleAdmin, roleMember, roleViewer:
	default:
		return AuthUser{}, fmt.Errorf("invalid role %q: must be admin, member, or viewer", role)
	}
	u, err := s.repo.UpdateUserRole(ctx, repository.UpdateUserRoleParams{
		ID:   targetID,
		Role: role,
	})
	if err != nil {
		return AuthUser{}, fmt.Errorf("updating user role: %w", err)
	}
	return AuthUser{
		ID:          u.ID,
		DisplayName: displayName(u.DisplayName),
		Role:        u.Role,
	}, nil
}

func (s *authService) CleanExpiredSessions(ctx context.Context) error {
	return s.repo.DeleteExpiredSessions(ctx)
}

// LoadGrants reads the caller's namespace_member rows in one query and returns
// them keyed by namespace ID.
//
// A user with no memberships gets an empty (non-nil) map rather than an error,
// because "member of nothing" is the ordinary state of a new account and must
// read as a clean deny at every capability check rather than as a failure.
//
// Role strings that no longer map to a known role are kept as-is: authz.Role
// grants nothing unless it is one of the five, so a row written by a future
// version denies instead of panicking.
func (s *authService) LoadGrants(ctx context.Context, userID pgtype.UUID) (map[string]authz.Role, error) {
	if !userID.Valid {
		return map[string]authz.Role{}, nil
	}
	rows, err := s.repo.ListNamespaceMembershipsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("loading namespace grants: %w", err)
	}
	out := make(map[string]authz.Role, len(rows))
	for _, m := range rows {
		out[uuidToStr(m.NamespaceID)] = authz.Role(m.Role)
	}
	return out, nil
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
