package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
	"github.com/pfenerty/ocidex/internal/secretbox"
)

func testBox(t *testing.T) *secretbox.Box {
	t.Helper()
	box, err := secretbox.New(map[string][]byte{"k1": bytes.Repeat([]byte{7}, secretbox.KeySize)}, "k1")
	if err != nil {
		t.Fatal(err)
	}
	return box
}

func ptr(s string) *string { return &s }

// fakeStore is a one-row registry table: what Create/Update write is what
// Get/List read back, so a test sees the stored form and the domain form.
type fakeStore struct{ row repository.Registry }

func (f *fakeStore) repo() *fakeRegistryRepo {
	return &fakeRegistryRepo{
		createFn: func(_ context.Context, arg repository.CreateRegistryParams) (repository.Registry, error) {
			f.row = repository.Registry{ID: arg.ID, Type: arg.Type, Url: arg.Url,
				WebhookSecret: arg.WebhookSecret, AuthToken: arg.AuthToken, AuthUsername: arg.AuthUsername}
			return f.row, nil
		},
		updateFn: func(_ context.Context, arg repository.UpdateRegistryParams) (repository.Registry, error) {
			f.row.WebhookSecret, f.row.AuthToken = arg.WebhookSecret, arg.AuthToken
			return f.row, nil
		},
		getFn: func(_ context.Context, _ pgtype.UUID) (repository.GetRegistryRow, error) {
			return repository.GetRegistryRow{Registry: f.row}, nil
		},
		listFn: func(_ context.Context, _ repository.ListRegistriesParams) ([]repository.ListRegistriesRow, error) {
			return []repository.ListRegistriesRow{{Registry: f.row}}, nil
		},
	}
}

func TestRegistryCredentials_EncryptedAtRest(t *testing.T) {
	is := is.New(t)
	ctx := context.Background()
	store := &fakeStore{}
	svc := &registryService{repo: store.repo(), box: testBox(t)}

	created, err := svc.Create(ctx, CreateRegistryParams{
		Name: "r", Type: "generic", URL: "https://r.example.com", ScanMode: "webhook",
		AuthUsername: ptr("bot"), AuthToken: ptr("ghp_token"), WebhookSecret: ptr("hook-secret"),
	})
	is.NoErr(err)

	// Stored form: encrypted, never the plaintext.
	is.True(store.row.ID.Valid) // Create supplies the row id
	is.True(strings.HasPrefix(store.row.AuthToken.String, "enc:v1:k1:"))
	is.True(strings.HasPrefix(store.row.WebhookSecret.String, "enc:v1:k1:"))
	is.True(!strings.Contains(store.row.AuthToken.String, "ghp_token"))

	// Domain form: plaintext on every read path.
	is.Equal(*created.AuthToken, "ghp_token")
	is.Equal(*created.WebhookSecret, "hook-secret")
	got, err := svc.Get(ctx, created.ID)
	is.NoErr(err)
	is.Equal(*got.AuthToken, "ghp_token")
	is.Equal(*got.WebhookSecret, "hook-secret")
	list, err := svc.List(ctx, VisibilityFilter{IsAdmin: true})
	is.NoErr(err)
	is.Equal(*list[0].AuthToken, "ghp_token")

	// Update re-encrypts what it writes.
	_, err = svc.Update(ctx, UpdateRegistryParams{
		ID: created.ID, Name: "r", Type: "generic", URL: "https://r.example.com", ScanMode: "webhook",
		AuthToken: ptr("ghp_rotated"), WebhookSecret: got.WebhookSecret,
	})
	is.NoErr(err)
	is.True(strings.HasPrefix(store.row.AuthToken.String, "enc:v1:k1:"))
	got, err = svc.Get(ctx, created.ID)
	is.NoErr(err)
	is.Equal(*got.AuthToken, "ghp_rotated")
	is.Equal(*got.WebhookSecret, "hook-secret")
}

func TestRegistryCredentials_LegacyPlaintextReads(t *testing.T) {
	is := is.New(t)
	id := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	store := &fakeStore{row: repository.Registry{
		ID:            id,
		AuthToken:     pgtype.Text{String: "legacy-token", Valid: true},
		WebhookSecret: pgtype.Text{String: "legacy-secret", Valid: true},
	}}
	svc := &registryService{repo: store.repo(), box: testBox(t)}

	got, err := svc.Get(context.Background(), uuidToStr(id))
	is.NoErr(err)
	is.Equal(*got.AuthToken, "legacy-token")
	is.Equal(*got.WebhookSecret, "legacy-secret")
}

// A ciphertext copied onto another row must not decrypt there.
func TestRegistryCredentials_BoundToRow(t *testing.T) {
	is := is.New(t)
	box := testBox(t)
	stored, err := sealCredential(box, colAuthToken, uuidToStr(pgtype.UUID{Bytes: [16]byte{1}, Valid: true}), ptr("tok"))
	is.NoErr(err)

	other := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	store := &fakeStore{row: repository.Registry{ID: other, AuthToken: stored}}
	svc := &registryService{repo: store.repo(), box: box}
	_, err = svc.Get(context.Background(), uuidToStr(other))
	is.True(err != nil)
}

// Without a key (non-production), credentials are stored as given.
func TestRegistryCredentials_NoKeyStoresPlaintext(t *testing.T) {
	is := is.New(t)
	store := &fakeStore{}
	svc := &registryService{repo: store.repo()}

	_, err := svc.Create(context.Background(), CreateRegistryParams{
		Name: "r", Type: "generic", URL: "https://r.example.com", ScanMode: "webhook",
		AuthToken: ptr("ghp_token"),
	})
	is.NoErr(err)
	is.Equal(store.row.AuthToken.String, "ghp_token")
}
