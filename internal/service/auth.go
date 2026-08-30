package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/pfenerty/ocidex/internal/authz"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/event"
	"github.com/pfenerty/ocidex/internal/repository"
)

// AuthUser is the authenticated principal attached to a request context.
type AuthUser struct {
	ID             pgtype.UUID
	GitHubID       int64
	GitHubUsername string
	Role           string
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

// AuthService handles GitHub OAuth, sessions, and API key management.
type AuthService interface {
	BuildAuthURL(state string) string
	ExchangeCodeForUser(ctx context.Context, code string) (AuthUser, error)
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
	pool      *pgxpool.Pool
	repo      repository.AuthRepository
	oauth2    *oauth2.Config
	cfg       *config.Config
	publisher event.Publisher
}

// NewAuthService constructs an AuthService.
func NewAuthService(pool *pgxpool.Pool, cfg *config.Config, publisher event.Publisher) AuthService {
	oc := &oauth2.Config{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		RedirectURL:  cfg.GitHubRedirectURL,
		Scopes:       []string{"read:user"},
		Endpoint:     github.Endpoint,
	}
	return &authService{
		pool:      pool,
		repo:      repository.New(pool),
		oauth2:    oc,
		cfg:       cfg,
		publisher: publisher,
	}
}

func (s *authService) BuildAuthURL(state string) string {
	return s.oauth2.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

func (s *authService) ExchangeCodeForUser(ctx context.Context, code string) (AuthUser, error) {
	token, err := s.oauth2.Exchange(ctx, code)
	if err != nil {
		return AuthUser{}, fmt.Errorf("exchanging oauth code: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return AuthUser{}, fmt.Errorf("building github user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return AuthUser{}, fmt.Errorf("fetching github user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AuthUser{}, fmt.Errorf("github user API returned %d", resp.StatusCode)
	}

	var ghUser struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		return AuthUser{}, fmt.Errorf("decoding github user: %w", err)
	}

	u, err := s.repo.UpsertUser(ctx, repository.UpsertUserParams{
		GithubID:       ghUser.ID,
		GithubUsername: ghUser.Login,
	})
	if err != nil {
		return AuthUser{}, fmt.Errorf("upserting user: %w", err)
	}

	return AuthUser{
		ID:             u.ID,
		GitHubID:       u.GithubID,
		GitHubUsername: u.GithubUsername,
		Role:           u.Role,
	}, nil
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
		ID:             row.UserID,
		GitHubID:       row.GithubID,
		GitHubUsername: row.GithubUsername,
		Role:           row.Role,
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
		ID:             row.UserID,
		GitHubID:       row.GithubID,
		GitHubUsername: row.GithubUsername,
		Role:           row.Role,
		APIKeyAuth:     true,
		APIKeyCaps:     caps,
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
		ID:             u.ID,
		GitHubID:       u.GithubID,
		GitHubUsername: u.GithubUsername,
		Role:           u.Role,
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
			ID:             u.ID,
			GitHubID:       u.GithubID,
			GitHubUsername: u.GithubUsername,
			Role:           u.Role,
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
		ID:             u.ID,
		GitHubID:       u.GithubID,
		GitHubUsername: u.GithubUsername,
		Role:           u.Role,
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
