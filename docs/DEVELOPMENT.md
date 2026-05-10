# Development Patterns

Concise reference for coding patterns in OCIDex. For technology rationale, see the [ADRs](adr/).

## Project Structure

```
cmd/ocidex/main.go        # Wiring: config → DB → repos → services → handlers → server
internal/api/              # HTTP handlers, chi routing, request/response types
internal/service/          # Business logic interfaces and implementations
internal/repository/       # Repository interfaces + sqlc-generated query code
internal/config/           # Config struct with env struct tags
pkg/                       # Public libraries (use sparingly)
tests/                     # Integration tests (testcontainers)
db/migrations/             # goose SQL migration files (also sqlc schema source)
db/queries/                # sqlc .sql query files
```

Each layer depends only on the layer below it. `api/` imports `service/`, `service/` imports `repository/`. Never skip layers.

## Stack Examples

### Example A: Create Artifact (POST)

**Route registration** (`internal/api/router.go`):
```go
r.Route("/api/v1", func(r chi.Router) {
    r.Post("/artifacts", h.CreateArtifact)
})
```

**Handler** (`internal/api/artifact.go`):
```go
func (h *Handler) CreateArtifact(w http.ResponseWriter, r *http.Request) {
    var req CreateArtifactRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        WriteError(w, ErrBadRequest("invalid JSON"))
        return
    }
    if err := req.Validate(); err != nil {
        WriteError(w, err)
        return
    }
    artifact, err := h.artifactService.Create(r.Context(), req.ToDomain())
    if err != nil {
        WriteError(w, err)
        return
    }
    WriteJSON(w, http.StatusCreated, artifact)
}
```

**Service interface** (`internal/service/artifact.go`):
```go
type ArtifactService interface {
    Create(ctx context.Context, a domain.Artifact) (*domain.Artifact, error)
}

func (s *artifactService) Create(ctx context.Context, a domain.Artifact) (*domain.Artifact, error) {
    slog.InfoContext(ctx, "creating artifact", "name", a.Name)
    result, err := s.repo.InsertArtifact(ctx, repository.InsertArtifactParams{...})
    if err != nil {
        return nil, fmt.Errorf("creating artifact: %w", err)
    }
    return mapToDomain(result), nil
}
```

**sqlc query** (`db/queries/artifact.sql`):
```sql
-- name: InsertArtifact :one
INSERT INTO artifacts (name, version, sbom_data)
VALUES ($1, $2, $3)
RETURNING *;
```

### Example B: Get Artifact by ID (GET)

```go
// Route
r.Get("/artifacts/{id}", h.GetArtifact)

// Handler
func (h *Handler) GetArtifact(w http.ResponseWriter, r *http.Request) {
    id, err := uuid.Parse(chi.URLParam(r, "id"))
    if err != nil {
        WriteError(w, ErrBadRequest("invalid artifact ID"))
        return
    }
    artifact, err := h.artifactService.GetByID(r.Context(), id)
    if err != nil {
        WriteError(w, err)
        return
    }
    WriteJSON(w, http.StatusOK, artifact)
}
```

## Error Types & HTTP Mapping

**Core types** (`internal/api/errors.go`):
```go
// APIError maps domain errors to HTTP responses.
type APIError struct {
    Code    int    `json:"-"`
    Message string `json:"error"`
    Err     error  `json:"-"`
}

func (e *APIError) Error() string { return e.Message }
func (e *APIError) Unwrap() error { return e.Err }

// ValidationError holds per-field errors.
type ValidationError struct {
    Fields map[string][]string `json:"errors"`
}
```

**Sentinel errors** (`internal/service/errors.go`):
```go
var (
    ErrNotFound  = errors.New("not found")
    ErrConflict  = errors.New("conflict")
)
```

**Error-handling helper** — single place that maps errors to HTTP responses:
```go
func WriteError(w http.ResponseWriter, err error) {
    var apiErr *APIError
    if errors.As(err, &apiErr) {
        WriteJSON(w, apiErr.Code, apiErr)
        return
    }
    var valErr *ValidationError
    if errors.As(err, &valErr) {
        WriteJSON(w, http.StatusUnprocessableEntity, valErr)
        return
    }
    switch {
    case errors.Is(err, service.ErrNotFound):
        WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
    case errors.Is(err, service.ErrConflict):
        WriteJSON(w, http.StatusConflict, map[string]string{"error": "conflict"})
    default:
        slog.Error("unhandled error", "err", err)
        WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
    }
}
```

No ad-hoc `http.Error()` calls in handlers. All errors flow through `WriteError`.

## Test-Driven Development

**Workflow:** Write test → run it (expect failure) → implement → run it (expect pass) → refactor.

### Unit Test — Service Layer

```go
func TestArtifactService_Create(t *testing.T) {
    is := is.New(t)

    tests := []struct {
        name    string
        input   domain.Artifact
        repoErr error
        wantErr error
    }{
        {
            name:  "success",
            input: domain.Artifact{Name: "myapp"},
        },
        {
            name:    "duplicate",
            input:   domain.Artifact{Name: "myapp"},
            repoErr: repository.ErrUniqueViolation,
            wantErr: service.ErrConflict,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            repo := &fakeArtifactRepo{err: tt.repoErr}
            svc := service.NewArtifactService(repo)

            _, err := svc.Create(context.Background(), tt.input)

            if tt.wantErr != nil {
                is.True(errors.Is(err, tt.wantErr))
            } else {
                is.NoErr(err)
            }
        })
    }
}
```

### HTTP Handler Test

```go
func TestGetArtifact_NotFound(t *testing.T) {
    is := is.New(t)
    svc := &fakeArtifactService{err: service.ErrNotFound}
    h := api.NewHandler(svc)

    r := httptest.NewRequest("GET", "/api/v1/artifacts/"+uuid.New().String(), nil)
    w := httptest.NewRecorder()

    // chi requires a route context for URL params
    rctx := chi.NewRouteContext()
    rctx.URLParams.Add("id", uuid.New().String())
    r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

    h.GetArtifact(w, r)

    is.Equal(w.Code, http.StatusNotFound)
}
```

### Integration Test — Repository with testcontainers

```go
func TestInsertArtifact_Integration(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping integration test")
    }
    is := is.New(t)

    ctx := context.Background()
    pg, err := postgres.Run(ctx, "postgres:16-alpine",
        postgres.WithDatabase("ocidex_test"),
        testcontainers.WithWaitStrategy(
            wait.ForLog("database system is ready to accept connections").
                WithOccurrence(2)),
    )
    t.Cleanup(func() { pg.Terminate(ctx) })
    is.NoErr(err)

    connStr, err := pg.ConnectionString(ctx, "sslmode=disable")
    is.NoErr(err)

    pool, err := pgxpool.New(ctx, connStr)
    is.NoErr(err)
    // Run migrations, then test queries against real Postgres.
}
```

### Testing diff/tree changes

Diff and dependency-tree code (`internal/service/changelog.go`,
`internal/service/search*.go`, `web/src/components/Diff*.tsx`,
`web/src/pages/Diff*.tsx`) has bitten us before with subtle contract
regressions that passed unit tests but broke real diffs. The rules
below codify what we learned from the post-launch fixes (`ocidex-e5b`):

1. **Every behavioral change starts with a failing test.** Write the
   test, run it, see it fail, then implement. The acceptance criterion
   on the beads issue should cite the test path.

2. **ADRs document contracts; tests must guard them.** ADR-0019 (diff
   identity), ADR-0020 (flavor axis), and ADR-0021 (backend-computed
   diff tree) all carry normative contracts. Each one references the
   beads issue that lands the implementing test (`bqh.27`, `bqh.36`,
   etc.). When you add or change an ADR contract, the implementing
   issue must add a test that fails before the implementation and
   passes after — "manual visual parity" closures (the `bqh.16`
   pattern) are not acceptable.

3. **Frontend follows ADR-0016 strictly.** Any new component touching
   API response shape gets a render test against a hand-crafted fixture
   matching the OpenAPI types. `@solidjs/testing-library` + `vitest` is
   set up; see `web/src/components/DiffTreeView.test.tsx` for the
   pattern (mock `@solidjs/router` + `~/api/queries`, render against a
   typed `DiffTree` fixture, assert the visible output).

4. **Parity rule for identity & matching tests.** Any test of a
   matching, grouping, or normalization function must include at least
   one *pair*: two inputs that should match vs. two that should not.
   Single-input tests prove syntax, not contract. The distro-version
   bug (`ocidex-e5b.2`) slipped past `TestNormalizeComponentPurl`
   because every fixture used a different opaque distro string at a
   single version — there were no two `alpine-*` versions paired
   against each other to prove they collapsed to the same identity.

5. **Round-trip the wire response in an integration test.** Service
   tests exercise pure Go; they don't catch bugs introduced by the
   request → handler → service → repository → JSON path. The
   `tests/diff_tree_test.go` integration test ingests two SBOMs via
   the public API, calls `GET /api/v1/sboms/diff-tree`, and asserts
   every field documented in ADR-0021. Add a similar round-trip test
   when you add a new endpoint that has a contract worth defending.

6. **Fixture-driven over hand-built where possible.** Backend diff
   fixtures live in `internal/service/testdata/sbom_diff/` and
   `internal/service/testdata/sbom_roots/`; tests load CycloneDX JSON
   and feed it through the same path production uses
   (`buildPackageMap`, `computeRootsAndDirect`). When you need to test
   "the same package across SBOMs", reach for fixtures over inline
   `componentIdentity` maps — the fixtures exercise more of the
   pipeline.

## Adding a New Enricher

Enrichers run asynchronously after SBOM ingestion. Each enricher fetches or derives metadata for a given subject and persists the result to the `enrichment` table.

**1. Create `internal/enrichment/<name>/<name>.go`** and implement `enrichment.Enricher`:

```go
package myenricher

import (
    "context"
    "encoding/json"
    "github.com/pfenerty/ocidex/internal/enrichment"
)

type Enricher struct{}

func NewEnricher() *Enricher { return &Enricher{} }

// Name returns the unique enricher identifier stored in enrichment.enricher_name.
func (e *Enricher) Name() string { return "my-enricher" }

// CanEnrich returns true when this enricher applies to the subject.
func (e *Enricher) CanEnrich(ref enrichment.SubjectRef) bool {
    return ref.ArtifactType == "container"
}

// Enrich fetches or derives metadata and returns it as JSON bytes.
func (e *Enricher) Enrich(ctx context.Context, ref enrichment.SubjectRef) ([]byte, error) {
    result := map[string]string{"example": ref.ArtifactName}
    return json.Marshal(result)
}
```

**2. Register in both entrypoints** — the in-process server and the NATS worker both build the registry at startup:

- `cmd/ocidex/main.go` → `setupEnrichmentExt()`
- `cmd/enrichment-worker/main.go` → `run()`

```go
enrichReg.Register(myenricher.NewEnricher())
```

**3. Available data in `SubjectRef`:**

| Field | Description |
|---|---|
| `SBOMId` | The SBOM being enriched |
| `ArtifactType` | e.g. `"container"`, `"library"` |
| `ArtifactName` | e.g. `"docker.io/myapp"` |
| `Digest` | `sha256:...` digest (containers) |
| `SubjectVersion` | Tag hint for index lookup |
| `Architecture` | Caller-supplied at ingest (may be empty) |
| `BuildDate` | Caller-supplied at ingest (may be empty) |

**4. Post-processing hooks** — the dispatcher automatically calls sufficiency promotion (marks the SBOM as fully enriched when both `imageVersion` and `architecture` are present) for `"oci-metadata"` and `"user"` enrichers. If your enricher also determines sufficiency, add its name to the check in `dispatcher.go:processSubject`.

### Fakes Over Mocks

Interfaces are small. Write manual fakes:

```go
type fakeArtifactRepo struct {
    result repository.Artifact
    err    error
}

func (f *fakeArtifactRepo) InsertArtifact(ctx context.Context, params repository.InsertArtifactParams) (repository.Artifact, error) {
    return f.result, f.err
}
```

No mock generation tools. If an interface is too large to fake by hand, it's too large — split it.
