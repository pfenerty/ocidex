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
	"slices"
	"sort"
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
	ID string
	// DisplayName is what to call this person in the UI. It is deliberately not
	// an identifier: it comes from whichever issuer last signed them in, and two
	// accounts may carry the same one.
	DisplayName string
	Role        string
	// APIKeyAuth reports whether this request was authenticated by an API key
	// rather than by a session cookie.
	APIKeyAuth bool
	// APIKeyID is the ID of the key that authenticated this request, empty
	// for a session. The audit log records it as the actor's key.
	APIKeyID string
	// APIKeyCaps is the capability ceiling declared on that key. It is only
	// ever a ceiling: what the caller may actually do is this set INTERSECTED
	// with their live namespace roles, which is what makes a demotion narrow
	// every key the member holds without a rotation.
	//
	// Meaningless unless APIKeyAuth — a session is the user themselves and
	// carries no ceiling, and an empty slice on a key means a key that may do
	// nothing but read public data.
	APIKeyCaps []authz.Capability
	// APIKeyClusterID is set when the key is a cluster agent credential.
	// Such a key may push that cluster's inventory and do
	// nothing else; the API layer rejects it on every other route.
	APIKeyClusterID string
	// APIKeyNamespaces is the namespace set of the key (ADR-0058 A2): the
	// namespaces it may act in and read privately. Nil is no narrowing, which
	// is a session and an unscoped personal key.
	APIKeyNamespaces []string
	// APIKeyKind is personal, agent or cluster; empty for a session.
	APIKeyKind string
	// APIKeyAgentLabel is what the holder calls an agent key's client.
	APIKeyAgentLabel string
	// APIKeyApprovalRequired lists the capabilities this key may use only
	// once a person approves the request (ADR-0058 A4).
	APIKeyApprovalRequired []authz.Capability
	// APIKeyScansPerHour and APIKeyWritesPerHour are an agent key's hourly
	// budgets (ADR-0058 A6), resolved from its overrides and the defaults.
	// Zero for every other credential, which has none.
	APIKeyScansPerHour  int
	APIKeyWritesPerHour int
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
	ID           string
	Name         string
	Prefix       string
	Capabilities []authz.Capability
	CreatedAt    time.Time
	LastUsedAt   *time.Time
	// ExpiresAt is when the key stops working; nil means never.
	ExpiresAt *time.Time
	// ClusterID is set for a cluster agent credential.
	ClusterID string
	// Kind is personal, agent or cluster.
	Kind string
	// Namespaces is the key's namespace set; nil is unscoped.
	Namespaces []string
	// AgentLabel names an agent key's client.
	AgentLabel string
	// ApprovalRequired lists capabilities held for approval.
	ApprovalRequired []authz.Capability
	// ScansPerHour and WritesPerHour are an agent key's budgets; nil means
	// the default.
	ScansPerHour  *int
	WritesPerHour *int
}

// uuidStrings renders a nullable UUID array: nil stays nil, the "unscoped"
// value, rather than becoming an empty slice that would scope to nothing.
func uuidStrings(ids []pgtype.UUID) []string {
	if ids == nil {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id.Valid {
			out = append(out, id.String())
		}
	}
	return out
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
	// Installation administration is not about a namespace, so a key limited
	// to namespaces never carries it (ADR-0058 A2).
	if c == authz.CapInstallationAdmin && u.APIKeyNamespaces != nil {
		return false
	}
	// Some decisions are never an agent's (A7), whatever the key row says.
	if u.APIKeyKind == KeyKindAgent && !authz.AgentMayHold(c) {
		return false
	}
	for _, held := range u.APIKeyCaps {
		if held == c {
			return true
		}
	}
	return false
}

// KeyCoversNamespace reports whether the credential may act in namespaceID: a
// session or unscoped key anywhere, a scoped key only in its namespaces. An
// empty namespaceID is an action not tied to a namespace, which a scoped key
// may not take.
func (u AuthUser) KeyCoversNamespace(namespaceID string) bool {
	if !u.APIKeyAuth || u.APIKeyNamespaces == nil {
		return true
	}
	return namespaceID != "" && slices.Contains(u.APIKeyNamespaces, namespaceID)
}

// RequiresApproval reports whether the credential may use c only once a person
// approves the request. A session never does: it is the person.
func (u AuthUser) RequiresApproval(c authz.Capability) bool {
	return u.APIKeyAuth && slices.Contains(u.APIKeyApprovalRequired, c)
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
	CreateSession(ctx context.Context, userID string) (plaintext string, err error)
	ValidateSession(ctx context.Context, token string) (AuthUser, error)
	DeleteSession(ctx context.Context, token string) error
	CreateAPIKey(ctx context.Context, userID string, name string, caps []authz.Capability) (plaintext string, err error)
	// CreateKey mints a key described by spec: a personal or agent key,
	// optionally narrowed to namespaces and expiring.
	CreateKey(ctx context.Context, userID string, spec KeySpec) (plaintext string, err error)
	// CreateExpiringAPIKey is CreateAPIKey for a key refused after expiresAt.
	// A zero expiresAt means never, which is what CreateAPIKey gives.
	CreateExpiringAPIKey(ctx context.Context, userID string, name string, caps []authz.Capability, expiresAt time.Time) (plaintext string, err error)
	ValidateAPIKey(ctx context.Context, rawKey string) (AuthUser, error)
	ListAPIKeys(ctx context.Context, userID string) ([]APIKeyMeta, error)
	DeleteAPIKey(ctx context.Context, userID string, keyID string) error
	GetUser(ctx context.Context, userID string) (AuthUser, error)
	ListUsers(ctx context.Context) ([]AuthUser, error)
	UpdateUserRole(ctx context.Context, targetID string, role string) (AuthUser, error)
	CleanExpiredSessions(ctx context.Context) error
	// ListIdentities returns the issuers this account can sign in with.
	ListIdentities(ctx context.Context, userID string) ([]LinkedIdentity, error)
	// LinkIdentity redeems a callback code and attaches the identity it
	// resolves to onto an account that already exists, instead of signing in as
	// whoever holds it.
	LinkIdentity(ctx context.Context, userID string, provider, code, verifier string) (LinkedIdentity, error)
	// UnlinkIdentity removes one of the account's identities, refusing to
	// remove the last one.
	UnlinkIdentity(ctx context.Context, userID string, identityID string) error
	// LoadGrants returns the user's namespace memberships keyed by namespace ID.
	// The API layer calls it once per authenticated request; see AuthUser.Grants
	// for why it is not folded into ValidateSession's row.
	LoadGrants(ctx context.Context, userID string) (map[string]authz.Role, error)
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
	u, err := s.resolveIdentity(ctx, id)
	if err != nil {
		return AuthUser{}, err
	}
	return s.promoteBootstrapAdmin(ctx, id, u)
}

// promoteBootstrapAdmin raises u to installation admin when the identity it
// signed in with is listed in BOOTSTRAP_ADMINS. It runs at sign-in rather than
// at startup so an operator can list an account before it exists.
//
// It only ever promotes. An admin who demotes a listed account by hand sees it
// promoted again at its next sign-in; removing it from the list is what makes a
// demotion stick.
func (s *authService) promoteBootstrapAdmin(ctx context.Context, id auth.Identity, u AuthUser) (AuthUser, error) {
	if u.Role == roleAdmin || !s.isBootstrapAdmin(id) {
		return u, nil
	}
	row, err := s.repo.UpdateUserRole(ctx, repository.UpdateUserRoleParams{ID: uuidOrNull(u.ID), Role: roleAdmin})
	if err != nil {
		return AuthUser{}, fmt.Errorf("promoting bootstrap admin: %w", err)
	}
	slog.InfoContext(ctx, "promoted bootstrap admin", "provider", id.Provider)
	u.Role = row.Role
	return u, nil
}

// signupOpen reports whether a first sign-in may create an account. Only
// SIGNUP_MODE=existing closes it; a BOOTSTRAP_ADMINS identity is let through
// regardless, or a closed installation could never get its first admin.
func (s *authService) signupOpen() bool {
	return s.cfg == nil || s.cfg.SignupMode != config.SignupExisting
}

// isBootstrapAdmin matches on (provider, subject) and nothing else — never on
// email, for the reason resolveIdentity gives.
func (s *authService) isBootstrapAdmin(id auth.Identity) bool {
	if s.cfg == nil {
		return false
	}
	for _, ref := range s.cfg.BootstrapAdmins {
		if ref.Provider == id.Provider && ref.Subject == id.Subject {
			return true
		}
	}
	return false
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
		return AuthUser{ID: u.ID.String(), DisplayName: displayName(u.DisplayName), Role: u.Role}, nil

	case errors.Is(err, pgx.ErrNoRows):
		if !s.signupOpen() && !s.isBootstrapAdmin(id) {
			return AuthUser{}, ErrSignupClosed
		}
		row, createErr := s.repo.CreateUserWithIdentity(ctx, newUserParams(id))
		if createErr == nil {
			return AuthUser{ID: row.ID.String(), DisplayName: displayName(row.DisplayName), Role: row.Role}, nil
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
		return AuthUser{ID: u.ID.String(), DisplayName: displayName(u.DisplayName), Role: u.Role}, nil

	default:
		return AuthUser{}, fmt.Errorf("looking up identity: %w", err)
	}
}

// newUserParams shapes the insert for a brand-new account. Nothing in it names
// an issuer: the provider and subject arrive as data, which is the whole point
// of user_identity.
func newUserParams(id auth.Identity) repository.CreateUserWithIdentityParams {
	return repository.CreateUserWithIdentityParams{
		Provider:    id.Provider,
		Subject:     id.Subject,
		DisplayName: pgtype.Text{String: id.DisplayName, Valid: id.DisplayName != ""},
		Email:       pgtype.Text{String: id.Email, Valid: id.Email != ""},
	}
}

// LinkedIdentity is one row of user_identity as its owner sees it.
//
// Subject is included because it is the only thing that tells two identities
// from the same issuer apart, and an owner deciding which one to unlink has to
// be able to. It is never shown to anybody else: the set of issuers a person
// signs in with, and their key at each, is a fingerprint they did not offer.
type LinkedIdentity struct {
	ID        string
	Provider  string
	Subject   string
	Email     string
	CreatedAt time.Time
}

func (s *authService) ListIdentities(ctx context.Context, userIDStr string) ([]LinkedIdentity, error) {
	userID, err := parseID(userIDStr)
	if err != nil {
		return nil, err
	}
	rows, err := s.repo.ListIdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing identities: %w", err)
	}
	out := make([]LinkedIdentity, len(rows))
	for i, r := range rows {
		out[i] = LinkedIdentity{
			ID:        r.ID.String(),
			Provider:  r.Provider,
			Subject:   r.Subject,
			Email:     r.Email.String,
			CreatedAt: r.CreatedAt.Time,
		}
	}
	return out, nil
}

// LinkIdentity attaches a second issuer to an account that already exists.
//
// An identity that already belongs to somebody else is refused outright rather
// than moved or merged. A silent merge is how an attacker who controls one
// identity absorbs another account: link the identity you hold to the account
// you want and the two become one. The only safe answer is that the identity is
// spoken for and nothing changes.
func (s *authService) LinkIdentity(ctx context.Context, userIDStr string, provider string, code string, verifier string) (LinkedIdentity, error) {
	userID, err := parseID(userIDStr)
	if err != nil {
		return LinkedIdentity{}, err
	}
	p, ok := s.providers[provider]
	if !ok {
		return LinkedIdentity{}, &ValidationError{Message: fmt.Sprintf("unknown identity provider %q", provider)}
	}
	id, err := p.Exchange(ctx, code, verifier)
	if err != nil {
		return LinkedIdentity{}, fmt.Errorf("exchanging code with %s: %w", provider, err)
	}
	if id.Subject == "" {
		return LinkedIdentity{}, fmt.Errorf("%s returned an identity with no subject", provider)
	}

	existing, err := s.repo.GetIdentity(ctx, repository.GetIdentityParams{
		Provider: id.Provider,
		Subject:  id.Subject,
	})
	switch {
	case err == nil && existing.UserID == userID:
		// Already linked here. Linking twice is a double-click, not an error.
		return identityFromRow(existing), nil
	case err == nil:
		return LinkedIdentity{}, fmt.Errorf("identity %s is linked elsewhere: %w", id.Provider, ErrConflict)
	case !errors.Is(err, pgx.ErrNoRows):
		return LinkedIdentity{}, fmt.Errorf("looking up identity: %w", err)
	}

	row, err := s.repo.CreateIdentity(ctx, repository.CreateIdentityParams{
		UserID:   userID,
		Provider: id.Provider,
		Subject:  id.Subject,
		Email:    pgtype.Text{String: id.Email, Valid: id.Email != ""},
	})
	if err != nil {
		// The UNIQUE (provider, subject) index is the real guard; the lookup
		// above only decides which answer to give. Two links racing land here.
		if isUniqueViolation(err) {
			return LinkedIdentity{}, fmt.Errorf("identity %s is linked elsewhere: %w", id.Provider, ErrConflict)
		}
		return LinkedIdentity{}, fmt.Errorf("linking identity: %w", err)
	}
	slog.Info("identity linked", "provider", id.Provider)

	return identityFromRow(row), nil
}

// UnlinkIdentity removes one identity from the caller's account.
//
// Removing the last one is refused. The account would still exist, still own
// namespaces and hold API keys, and nobody could ever sign in to it again;
// deleting an account is a different operation and this is not it.
func (s *authService) UnlinkIdentity(ctx context.Context, userIDStr string, identityIDStr string) error {
	userID, err := parseID(userIDStr)
	if err != nil {
		return err
	}
	identityID, err := parseID(identityIDStr)
	if err != nil {
		return err
	}
	count, err := s.repo.CountIdentitiesByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("counting identities: %w", err)
	}
	if count <= 1 {
		return fmt.Errorf("last identity on the account: %w", ErrConflict)
	}
	rows, err := s.repo.DeleteIdentity(ctx, repository.DeleteIdentityParams{ID: identityID, UserID: userID})
	if err != nil {
		return fmt.Errorf("unlinking identity: %w", err)
	}
	if rows == 0 {
		// Scoped by user_id, so somebody else's identity is indistinguishable
		// from one that does not exist. That is the intended answer.
		return fmt.Errorf("identity: %w", ErrNotFound)
	}

	return nil
}

func identityFromRow(r repository.UserIdentity) LinkedIdentity {
	return LinkedIdentity{
		ID:        r.ID.String(),
		Provider:  r.Provider,
		Subject:   r.Subject,
		Email:     r.Email.String,
		CreatedAt: r.CreatedAt.Time,
	}
}

func (s *authService) CreateSession(ctx context.Context, userIDStr string) (string, error) {
	userID, err := parseID(userIDStr)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating session token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256hex(plaintext)

	expiry := time.Now().Add(time.Duration(s.cfg.SessionMaxAgeDays) * 24 * time.Hour)
	_, err = s.repo.CreateSession(ctx, repository.CreateSessionParams{
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
		return AuthUser{}, credentialLookupError("session", err)
	}
	return AuthUser{
		ID:          row.UserID.String(),
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
		s.publisher.Publish(ctx, event.UserLoggedOut, event.UserLoggedOutData{UserID: uuidOrNull(user.ID)})
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
func (s *authService) CreateAPIKey(ctx context.Context, userID string, name string, caps []authz.Capability) (string, error) {
	return s.CreateExpiringAPIKey(ctx, userID, name, caps, time.Time{})
}

// CreateExpiringAPIKey mints a key that is refused once expiresAt has passed;
// a zero expiresAt never expires. An expiry in the past is rejected rather than
// minting a key that is dead on arrival.
func (s *authService) CreateExpiringAPIKey(ctx context.Context, userIDStr string, name string, caps []authz.Capability, expiresAt time.Time) (string, error) {
	return s.CreateKey(ctx, userIDStr, KeySpec{Name: name, Capabilities: caps, ExpiresAt: expiresAt, Kind: KeyKindPersonal})
}

// Key kinds (ADR-0058 A1). A cluster key is minted only by the cluster
// credential path, never here.
const (
	KeyKindPersonal = "personal"
	KeyKindAgent    = "agent"
	KeyKindCluster  = "cluster"
)

// KeySpec describes a key to mint.
type KeySpec struct {
	Name         string
	Capabilities []authz.Capability
	// ExpiresAt zero is a key that never expires.
	ExpiresAt time.Time
	// Kind is KeyKindPersonal or KeyKindAgent; empty is personal.
	Kind string
	// Namespaces narrows the key to these namespaces (ADR-0058 A2). Nil is
	// every namespace the holder belongs to, allowed only on a personal key.
	Namespaces []string
	// AgentLabel names an agent key's client, for display and audit.
	AgentLabel string
	// ApprovalRequired lists capabilities the key may use only once a person
	// approves each request. Each must be mutating and within Capabilities.
	ApprovalRequired []authz.Capability
	// Preset names an authz.Preset for an agent key; it sets Capabilities and
	// adds its approval-required set to ApprovalRequired.
	Preset string
	// ScansPerHour and WritesPerHour override an agent key's default budgets,
	// up to MaxAgentScansPerHour and MaxAgentWritesPerHour.
	ScansPerHour  *int
	WritesPerHour *int
	// IsAdmin is the holder's installation role, which decides which
	// namespaces they may name.
	IsAdmin bool
}

// normalizeKeySpec fills spec's defaults and validates everything that needs
// no database: kind, expiry, capability names and the approval-required set.
func normalizeKeySpec(spec KeySpec) (KeySpec, error) {
	if spec.Kind == "" {
		spec.Kind = KeyKindPersonal
	}
	if spec.Kind != KeyKindPersonal && spec.Kind != KeyKindAgent {
		return spec, &ValidationError{Message: fmt.Sprintf("kind must be %q or %q", KeyKindPersonal, KeyKindAgent)}
	}
	if !spec.ExpiresAt.IsZero() && !spec.ExpiresAt.After(time.Now()) {
		return spec, &ValidationError{Message: "expiresAt must be in the future"}
	}
	if spec.Kind == KeyKindAgent {
		var err error
		if spec, err = normalizeAgentSpec(spec); err != nil {
			return spec, err
		}
	} else if spec.Preset != "" {
		return spec, &ValidationError{Message: "presets are for agent keys"}
	}
	if len(spec.Capabilities) == 0 {
		spec.Capabilities = authz.AllCapabilities()
	}
	return spec, validateKeyCapabilities(spec)
}

// validateKeyCapabilities checks the capability names and that every
// approval-required capability is an approvable one the key carries.
func validateKeyCapabilities(spec KeySpec) error {
	for _, c := range spec.Capabilities {
		if !c.Valid() {
			return &ValidationError{Message: fmt.Sprintf("unknown capability %q", c)}
		}
	}
	for _, c := range spec.ApprovalRequired {
		approvable := c.Mutating() && c != authz.CapReadSecret && c != authz.CapInstallationAdmin
		if !c.Valid() || !approvable || !slices.Contains(spec.Capabilities, c) {
			return &ValidationError{Message: fmt.Sprintf("approvalRequired %q must be a mutating capability the key carries", c)}
		}
	}
	return nil
}

// Agent key lifetimes (ADR-0058 A3): an agent key always expires.
const (
	AgentKeyDefaultTTL = 30 * 24 * time.Hour
	AgentKeyMaxTTL     = 90 * 24 * time.Hour
)

// normalizeAgentSpec applies the agent-key rules: a preset or an explicit
// capability list (never the "everything" an empty list means), none of the
// capabilities an agent may never hold, and an expiry within AgentKeyMaxTTL,
// defaulting to AgentKeyDefaultTTL.
func normalizeAgentSpec(spec KeySpec) (KeySpec, error) {
	if spec.Preset != "" {
		p, ok := authz.PresetByName(spec.Preset)
		if !ok {
			return spec, &ValidationError{Message: fmt.Sprintf("unknown preset %q", spec.Preset)}
		}
		if len(spec.Capabilities) > 0 {
			return spec, &ValidationError{Message: "give a preset or capabilities, not both"}
		}
		spec.Capabilities = p.Capabilities
		for _, c := range p.ApprovalRequired {
			if !slices.Contains(spec.ApprovalRequired, c) {
				spec.ApprovalRequired = append(spec.ApprovalRequired, c)
			}
		}
	}
	if len(spec.Capabilities) == 0 {
		return spec, &ValidationError{Message: "an agent key needs a preset or an explicit capability list"}
	}
	for _, c := range spec.Capabilities {
		if !authz.AgentMayHold(c) {
			return spec, &ValidationError{Message: fmt.Sprintf("an agent key may not carry %q", c)}
		}
	}
	if err := validateBudget("scansPerHour", spec.ScansPerHour, MaxAgentScansPerHour); err != nil {
		return spec, err
	}
	if err := validateBudget("writesPerHour", spec.WritesPerHour, MaxAgentWritesPerHour); err != nil {
		return spec, err
	}
	now := time.Now()
	if spec.ExpiresAt.IsZero() {
		spec.ExpiresAt = now.Add(AgentKeyDefaultTTL)
	}
	if spec.ExpiresAt.After(now.Add(AgentKeyMaxTTL)) {
		return spec, &ValidationError{Message: "an agent key may last at most 90 days"}
	}
	return spec, nil
}

// CreateKey mints a key described by spec.
func (s *authService) CreateKey(ctx context.Context, userIDStr string, spec KeySpec) (string, error) {
	userID, err := parseID(userIDStr)
	if err != nil {
		return "", err
	}
	spec, err = normalizeKeySpec(spec)
	if err != nil {
		return "", err
	}
	name, caps, expiresAt := spec.Name, spec.Capabilities, spec.ExpiresAt
	namespaceIDs, err := s.keyNamespaces(ctx, userID, spec)
	if err != nil {
		return "", err
	}
	plaintext, hash, prefix, err := newAPIKeyMaterial()
	if err != nil {
		return "", err
	}

	_, err = s.repo.CreateAPIKey(ctx, repository.CreateAPIKeyParams{
		UserID:  userID,
		Name:    name,
		KeyHash: hash,
		Prefix:  prefix,

		Capabilities: authz.Strings(caps),
		ExpiresAt:    pgtype.Timestamptz{Time: expiresAt, Valid: !expiresAt.IsZero()},
		Kind:         spec.Kind,
		NamespaceIds: namespaceIDs,
		AgentLabel:   pgtype.Text{String: spec.AgentLabel, Valid: spec.AgentLabel != ""},
		// Never NULL: the column is NOT NULL and "none" is an empty array.
		ApprovalRequired: append([]string{}, authz.Strings(spec.ApprovalRequired)...),
		ScansPerHour:     int4Of(spec.ScansPerHour),
		WritesPerHour:    int4Of(spec.WritesPerHour),
	})
	if err != nil {
		return "", fmt.Errorf("creating api key: %w", err)
	}
	return plaintext, nil
}

// lastUsedResolution is how stale api_key.last_used_at may get before a
// request writes it again. TouchAPIKeyLastUsed enforces the same interval in
// SQL, which also collapses a burst of concurrent requests to one write.
const lastUsedResolution = time.Minute

// touchLastUsed records that a key was used, at most once per
// lastUsedResolution. It runs inline rather than in a detached goroutine, so it
// is bounded by the request and adds no unbounded work under a flood of
// requests; a failure is logged and never fails the request.
func (s *authService) touchLastUsed(ctx context.Context, id pgtype.UUID, last pgtype.Timestamptz) {
	if last.Valid && time.Since(last.Time) < lastUsedResolution {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.repo.TouchAPIKeyLastUsed(ctx, id); err != nil {
		slog.WarnContext(ctx, "touch api key last used", "err", err)
	}
}

// newAPIKeyMaterial generates a key's plaintext with the hash stored for it
// and the prefix shown for it. Shared by ordinary keys and cluster agent
// credentials, which are the same row with a cluster binding.
func newAPIKeyMaterial() (plaintext, hash, prefix string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", "", fmt.Errorf("generating api key: %w", err)
	}
	plaintext = "ocidex_" + base64.RawURLEncoding.EncodeToString(raw)
	prefix = plaintext
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	return plaintext, sha256hex(plaintext), prefix, nil
}

// credentialLookupError maps a failed credential lookup. Only "no rows" means
// the credential is unknown (ErrNotFound, which callers answer with 401);
// anything else is a server fault, and must not reach the caller as a 401 that
// sends operators debugging credentials during a database outage.
func credentialLookupError(what string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%s not found: %w", what, ErrNotFound)
	}
	return fmt.Errorf("looking up %s: %w", what, err)
}

func (s *authService) ValidateAPIKey(ctx context.Context, rawKey string) (AuthUser, error) {
	row, err := s.repo.GetAPIKeyByHash(ctx, sha256hex(rawKey))
	if err != nil {
		return AuthUser{}, credentialLookupError("api key", err)
	}
	s.touchLastUsed(ctx, row.ID, row.LastUsedAt)
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
		ID:          row.UserID.String(),
		DisplayName: displayName(row.DisplayName),
		Role:        row.Role,
		APIKeyAuth:  true,
		APIKeyID:    row.ID.String(),
		APIKeyCaps:  caps,
		// Empty for an ordinary key. Set, it confines the key to pushing
		// this one cluster's inventory.
		APIKeyClusterID:  row.ClusterID.String(),
		APIKeyKind:       row.Kind,
		APIKeyNamespaces: uuidStrings(row.NamespaceIds),
		APIKeyAgentLabel: row.AgentLabel.String,
		// Same narrowing rule as the ceiling: unknown names are dropped.
		APIKeyApprovalRequired: validCapabilities(row.ApprovalRequired),
		APIKeyScansPerHour:     agentLimit(int4Ptr(row.ScansPerHour), DefaultAgentScansPerHour),
		APIKeyWritesPerHour:    agentLimit(int4Ptr(row.WritesPerHour), DefaultAgentWritesPerHour),
	}, nil
}

// keyNamespaces validates spec's namespace set and returns it as UUIDs. An
// agent key must name at least one namespace; every namespace named must exist
// and be one the holder may act in (any, for an installation admin).
func (s *authService) keyNamespaces(ctx context.Context, userID pgtype.UUID, spec KeySpec) ([]pgtype.UUID, error) {
	if len(spec.Namespaces) == 0 {
		if spec.Kind == KeyKindAgent {
			return nil, &ValidationError{Message: "an agent key must be limited to at least one namespace"}
		}
		return nil, nil
	}
	seen := map[string]bool{}
	ids := make([]pgtype.UUID, 0, len(spec.Namespaces))
	for _, n := range spec.Namespaces {
		id, err := parseID(n)
		if err != nil {
			return nil, &ValidationError{Message: fmt.Sprintf("namespace %q is not a valid id", n)}
		}
		if !seen[id.String()] {
			seen[id.String()] = true
			ids = append(ids, id)
		}
	}
	n, err := s.repo.CountKeyNamespacesAllowed(ctx, repository.CountKeyNamespacesAllowedParams{
		NamespaceIds: ids,
		IsAdmin:      spec.IsAdmin,
		UserID:       userID,
	})
	if err != nil {
		return nil, fmt.Errorf("checking key namespaces: %w", err)
	}
	if int(n) != len(ids) {
		return nil, &ValidationError{Message: "a key can only be limited to namespaces you belong to"}
	}
	return ids, nil
}

func (s *authService) ListAPIKeys(ctx context.Context, userIDStr string) ([]APIKeyMeta, error) {
	userID, err := parseID(userIDStr)
	if err != nil {
		return nil, err
	}
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
			ID:               r.ID.String(),
			Name:             r.Name,
			Prefix:           r.Prefix,
			Capabilities:     caps,
			CreatedAt:        r.CreatedAt.Time,
			ClusterID:        r.ClusterID.String(),
			Kind:             r.Kind,
			Namespaces:       uuidStrings(r.NamespaceIds),
			AgentLabel:       r.AgentLabel.String,
			ApprovalRequired: validCapabilities(r.ApprovalRequired),
			ScansPerHour:     int4Ptr(r.ScansPerHour),
			WritesPerHour:    int4Ptr(r.WritesPerHour),
		}
		if r.LastUsedAt.Valid {
			t := r.LastUsedAt.Time
			m.LastUsedAt = &t
		}
		if r.ExpiresAt.Valid {
			t := r.ExpiresAt.Time
			m.ExpiresAt = &t
		}
		out[i] = m
	}
	return out, nil
}

func (s *authService) DeleteAPIKey(ctx context.Context, userIDStr string, keyIDStr string) error {
	userID, err := parseID(userIDStr)
	if err != nil {
		return err
	}
	keyID, err := parseID(keyIDStr)
	if err != nil {
		return err
	}
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

func (s *authService) GetUser(ctx context.Context, userIDStr string) (AuthUser, error) {
	userID, err := parseID(userIDStr)
	if err != nil {
		return AuthUser{}, err
	}
	u, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		return AuthUser{}, fmt.Errorf("getting user: %w", err)
	}
	return AuthUser{
		ID:          u.ID.String(),
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
			ID:          u.ID.String(),
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

func (s *authService) UpdateUserRole(ctx context.Context, targetIDStr string, role string) (AuthUser, error) {
	targetID, err := parseID(targetIDStr)
	if err != nil {
		return AuthUser{}, err
	}
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
		ID:          u.ID.String(),
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
func (s *authService) LoadGrants(ctx context.Context, userIDStr string) (map[string]authz.Role, error) {
	userID, err := parseID(userIDStr)
	if err != nil {
		return nil, err
	}
	if !userID.Valid {
		return map[string]authz.Role{}, nil
	}
	rows, err := s.repo.ListNamespaceMembershipsForUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("loading namespace grants: %w", err)
	}
	out := make(map[string]authz.Role, len(rows))
	for _, m := range rows {
		out[m.NamespaceID.String()] = authz.Role(m.Role)
	}
	return out, nil
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func int4Ptr(v pgtype.Int4) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int32)
	return &n
}

func int4Of(p *int) pgtype.Int4 {
	if p == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: int32(*p), Valid: true} //nolint:gosec // bounded by validation
}

// validateBudget checks an optional budget override against its maximum.
func validateBudget(name string, v *int, maxValue int) error {
	if v != nil && (*v < 0 || *v > maxValue) {
		return &ValidationError{Message: fmt.Sprintf("%s must be 0..%d", name, maxValue)}
	}
	return nil
}
