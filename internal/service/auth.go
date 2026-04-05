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

	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/repository"
)

// AuthUser is the authenticated principal attached to a request context.
type AuthUser struct {
	ID             pgtype.UUID
	GitHubID       int64
	GitHubUsername string
	Role           string
}

// APIKeyMeta is the display-safe representation of an API key (no hash).
type APIKeyMeta struct {
	ID         pgtype.UUID
	Name       string
	Prefix     string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// AuthService handles GitHub OAuth, sessions, and API key management.
type AuthService interface {
	BuildAuthURL(state string) string
	ExchangeCodeForUser(ctx context.Context, code string) (AuthUser, error)
	CreateSession(ctx context.Context, userID pgtype.UUID) (plaintext string, err error)
	ValidateSession(ctx context.Context, token string) (AuthUser, error)
	DeleteSession(ctx context.Context, token string) error
	CreateAPIKey(ctx context.Context, userID pgtype.UUID, name string) (plaintext string, err error)
	ValidateAPIKey(ctx context.Context, rawKey string) (AuthUser, error)
	ListAPIKeys(ctx context.Context, userID pgtype.UUID) ([]APIKeyMeta, error)
	DeleteAPIKey(ctx context.Context, userID pgtype.UUID, keyID pgtype.UUID) error
	GetUser(ctx context.Context, userID pgtype.UUID) (AuthUser, error)
	ListUsers(ctx context.Context) ([]AuthUser, error)
	UpdateUserRole(ctx context.Context, targetID pgtype.UUID, role string) (AuthUser, error)
	CleanExpiredSessions(ctx context.Context) error
}

type authService struct {
	pool   *pgxpool.Pool
	repo   repository.AuthRepository
	oauth2 *oauth2.Config
	cfg    *config.Config
}

// NewAuthService constructs an AuthService.
func NewAuthService(pool *pgxpool.Pool, cfg *config.Config) AuthService {
	oc := &oauth2.Config{
		ClientID:     cfg.GitHubClientID,
		ClientSecret: cfg.GitHubClientSecret,
		RedirectURL:  cfg.GitHubRedirectURL,
		Scopes:       []string{"read:user"},
		Endpoint:     github.Endpoint,
	}
	return &authService{
		pool:   pool,
		repo:   repository.New(pool),
		oauth2: oc,
		cfg:    cfg,
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
	return s.repo.DeleteSession(ctx, sha256hex(token))
}

func (s *authService) CreateAPIKey(ctx context.Context, userID pgtype.UUID, name string) (string, error) {
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
	return AuthUser{
		ID:             row.UserID,
		GitHubID:       row.GithubID,
		GitHubUsername: row.GithubUsername,
		Role:           row.Role,
	}, nil
}

func (s *authService) ListAPIKeys(ctx context.Context, userID pgtype.UUID) ([]APIKeyMeta, error) {
	rows, err := s.repo.ListAPIKeysByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("listing api keys: %w", err)
	}
	out := make([]APIKeyMeta, len(rows))
	for i, r := range rows {
		m := APIKeyMeta{
			ID:        r.ID,
			Name:      r.Name,
			Prefix:    r.Prefix,
			CreatedAt: r.CreatedAt.Time,
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

func (s *authService) UpdateUserRole(ctx context.Context, targetID pgtype.UUID, role string) (AuthUser, error) {
	switch role {
	case "admin", "member", "viewer":
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

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
