package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/service"
)

// timeoutSBOMService fails the way a request that outran router.go's
// middleware.Timeout does: the deadline error wrapped by whatever layer noticed
// it first, never returned bare.
type timeoutSBOMService struct {
	failSBOMService
}

func (t *timeoutSBOMService) Ingest(_ context.Context, _ *cdx.BOM, _ []byte, _ service.IngestParams) (pgtype.UUID, error) {
	return pgtype.UUID{}, fmt.Errorf("querying components: %w", context.DeadlineExceeded)
}

func TestMapServiceError_NotFound(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &notFoundSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/3e671687-395b-41f5-a30f-a58921a69b79", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusNotFound)
}

func TestMapServiceError_InternalError(t *testing.T) {
	is := is.New(t)
	router := newTestRouterWithAuth(&failSBOMService{}, &fakeSearchService{}, memberAuthSvc())

	body := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"type": "library", "name": "test-lib", "version": "1.0.0"}
		]
	}`
	r := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer member-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusInternalServerError)
}

func TestBadUUIDPathParamIsRejected(t *testing.T) {
	is := is.New(t)
	router := newTestRouter(&fakeSBOMService{}, &fakeSearchService{})

	r := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/not-a-uuid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusUnprocessableEntity)
}

// TestMapServiceError_DeadlineExceeded pins the distinction the 500 used to
// erase: a query that ran out of time is not a server that broke, and reporting
// it as one sent three real timeouts to production disguised as crashes.
func TestMapServiceError_DeadlineExceeded(t *testing.T) {
	is := is.New(t)
	router := newTestRouterWithAuth(&timeoutSBOMService{}, &fakeSearchService{}, memberAuthSvc())

	body := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"type": "library", "name": "test-lib", "version": "1.0.0"}
		]
	}`
	r := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer member-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	is.Equal(w.Code, http.StatusGatewayTimeout)
}
