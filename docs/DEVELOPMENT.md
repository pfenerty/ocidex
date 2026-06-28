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

OCIDex uses [huma v2](https://huma.rocks/) for all API handlers. Huma generates the OpenAPI spec from Go types; there is no separate spec file to maintain.

### Example A: Ingest SBOM (POST with raw body)

**Route registration** (`internal/api/router.go`):
```go
func registerSBOMOps(api huma.API, h *Handler) {
    memberMW := RequireMember(api)
    huma.Register(api, huma.Operation{
        OperationID:   "ingest-sbom",
        Method:        http.MethodPost,
        Path:          "/api/v1/sboms",
        Summary:       "Ingest an SBOM",
        Tags:          []string{"SBOMs"},
        MaxBodyBytes:  maxSBOMBodyBytes,
        DefaultStatus: http.StatusCreated,
        Middlewares:   huma.Middlewares{memberMW},
    }, h.IngestSBOM)
}
```

**Input/output types** (`internal/api/types.go`):
```go
type IngestSBOMInput struct {
    RawBody      []byte
    Version      string `query:"version"      doc:"Image version/tag"`
    Architecture string `query:"architecture" doc:"Image architecture (e.g. amd64, arm64)"`
    BuildDate    string `query:"build_date"   doc:"Image build date (RFC3339)"`
}

type IngestSBOMOutput struct {
    Body struct {
        ID             string `json:"id"             doc:"UUID of the created SBOM"`
        Status         string `json:"status"         example:"accepted"`
        ComponentCount int    `json:"componentCount" doc:"Number of components"`
    }
}
```

**Handler** (`internal/api/sbom.go`):
```go
func (h *Handler) IngestSBOM(ctx context.Context, input *IngestSBOMInput) (*IngestSBOMOutput, error) {
    if user, ok := UserFromContext(ctx); ok && !isWriteAllowed(user) {
        return nil, huma.Error403Forbidden("read-only API key cannot perform write operations")
    }
    bom := new(cdx.BOM)
    if err := cdx.NewBOMDecoder(bytes.NewReader(input.RawBody), cdx.BOMFileFormatJSON).Decode(bom); err != nil {
        return nil, huma.Error400BadRequest("invalid CycloneDX JSON: " + err.Error())
    }
    sbomID, err := h.sbomService.Ingest(ctx, bom, input.RawBody, service.IngestParams{...})
    if err != nil {
        return nil, mapServiceError(err)
    }
    out := &IngestSBOMOutput{}
    out.Body.ID = sbomID.String()
    out.Body.Status = "accepted"
    return out, nil
}
```

### Example B: Get SBOM by ID (GET with path param)

**Types** (`internal/api/types.go`):
```go
type GetSBOMInput struct {
    ID      string `path:"id" doc:"SBOM UUID" format:"uuid"`
    Include string `query:"include" doc:"Set to 'raw' to include the raw BOM JSON"`
}

type GetSBOMOutput struct {
    Body service.SBOMDetail
}
```

**Handler** (`internal/api/sbom.go`):
```go
func (h *Handler) GetSBOM(ctx context.Context, input *GetSBOMInput) (*GetSBOMOutput, error) {
    id, err := parseUUID(input.ID)
    if err != nil {
        return nil, err  // parseUUID returns huma.Error400BadRequest on invalid input
    }
    detail, err := h.sbomService.GetSBOM(ctx, id, input.Include == "raw")
    if err != nil {
        return nil, mapServiceError(err)
    }
    return &GetSBOMOutput{Body: *detail}, nil
}
```

## Error Handling

Handlers return `error` directly. Use huma helpers for HTTP errors; use `mapServiceError` to convert service sentinel errors:

```go
// internal/api/errors.go
func mapServiceError(err error) error {
    switch {
    case errors.Is(err, service.ErrNotFound):
        return huma.Error404NotFound("not found")
    case errors.Is(err, service.ErrConflict):
        return huma.Error409Conflict("conflict")
    default:
        return err  // huma renders unrecognized errors as 500
    }
}
```

**Service sentinel errors** (`internal/service/errors.go`):
```go
var (
    ErrNotFound = errors.New("not found")
    ErrConflict = errors.New("conflict")
)
```

Never call `http.Error()` or write directly to `http.ResponseWriter` in a huma handler — return errors instead. Huma serializes them as RFC 7807 problem details.

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

Huma handlers accept typed inputs, so test them by calling the handler directly with a constructed input rather than routing through HTTP:

```go
func TestGetSBOM_NotFound(t *testing.T) {
    is := is.New(t)
    svc := &fakeSBOMService{err: service.ErrNotFound}
    h := api.NewHandler(svc, ...)

    _, err := h.GetSBOM(context.Background(), &api.GetSBOMInput{ID: uuid.New().String()})

    var humaErr huma.StatusError
    is.True(errors.As(err, &humaErr))
    is.Equal(humaErr.GetStatus(), http.StatusNotFound)
}
```

For full integration tests that exercise routing, auth middleware, and serialization, use `httptest.NewServer` with the router returned by `api.NewRouter`.

See `internal/api/sbom_test.go` and `internal/api/auth_boundary_test.go` for working examples.

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

**5. Create a per-enricher worker binary** — each enricher needs its own `cmd/` binary, Docker image, and CI task (see [ADR-033](adr/0033-per-enricher-services.md)):

- **`cmd/<name>-worker/main.go`** (~30 lines): call `enrichmentworker.Run` with `EnricherName: "<name>"` and a unique `HintDurable: "enrich-hint-<name>"`. See `cmd/provenance-worker/main.go` as the canonical example.
- **`internal/service/enrichjob.go`**: add `"<name>"` to the `knownEnrichers` slice so an `enrichment_jobs` row is created for every new SBOM.
- **`docker/Dockerfile`**: add a `go build` line in the builder stage and a `FROM gcr.io/distroless/static-debian12:nonroot AS <name>-worker` runtime stage.
- **`.tektonic/jobs/image-build/spec.ts`**: add `["<name>-worker", "docker/Dockerfile", "<name>-worker"]` to `imageSpecs`, then run `make tekton-synth`.

**Per-host resolvers** — When an enricher needs per-registry behavior (insecure HTTP, credentials, trust anchors), use Option closures and resolver functions rather than baking config into the struct. Define a resolver type (e.g. `type TrustResolver func(ctx context.Context, host string) (mode, pemKey string)`), expose `With*` options on the enricher, and construct the resolver from `internal/service/registry.go` (`BuildTrustLookup`, `BuildInsecureHostLookup`) inside the worker's `EnricherFactory`. See `internal/enrichment/provenance/provenance.go` and `cmd/provenance-worker/main.go` for the full pattern.

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
