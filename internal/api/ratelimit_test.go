package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/api"
	"github.com/pfenerty/ocidex/internal/config"
	"github.com/pfenerty/ocidex/internal/service"
)

func TestClientIP(t *testing.T) {
	proxies := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	tests := []struct {
		name    string
		trusted []netip.Prefix
		remote  string
		xff     []string
		want    string
	}{
		{"no proxy trusted ignores XFF", nil, "203.0.113.9:5000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"untrusted peer's XFF is ignored", proxies, "203.0.113.9:5000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"trusted proxy yields the client", proxies, "10.0.0.2:5000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"right-most untrusted hop wins over a spoofed left", proxies, "10.0.0.2:5000",
			[]string{"6.6.6.6, 198.51.100.1, 10.0.0.3"}, "198.51.100.1"},
		{"multiple XFF headers form one list", proxies, "10.0.0.2:5000",
			[]string{"6.6.6.6", "198.51.100.1"}, "198.51.100.1"},
		{"all hops trusted yields the left-most", proxies, "10.0.0.2:5000", []string{"10.0.0.7, 10.0.0.3"}, "10.0.0.7"},
		{"garbage hop stops the walk", proxies, "10.0.0.2:5000", []string{"198.51.100.1, nonsense"}, "10.0.0.2"},
		{"trusted proxy without XFF is the client", proxies, "10.0.0.2:5000", nil, "10.0.0.2"},
		{"IPv4-mapped IPv6 peer is unmapped", proxies, "[::ffff:10.0.0.2]:5000", []string{"198.51.100.1"}, "198.51.100.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			is.Equal(api.NewClientIPResolver(api.ClientIPPolicy{TrustedProxies: tt.trusted}).ClientIP(r), tt.want)
		})
	}
}

// TestClientIPHops covers TRUSTED_PROXY_HOPS (ocidex-w6st): N proxies in
// front of the API, so the client is the N-th X-Forwarded-For entry from the
// right, whatever a client prepended to the left of it.
func TestClientIPHops(t *testing.T) {
	tests := []struct {
		name   string
		hops   int
		trust  []netip.Prefix
		remote string
		xff    []string
		want   string
	}{
		{"one proxy: right-most entry", 1, nil, "10.244.1.5:5000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"one proxy ignores a spoofed prefix", 1, nil, "10.244.1.5:5000", []string{"6.6.6.6, 198.51.100.1"}, "198.51.100.1"},
		{"two proxies: second from the right", 2, nil, "10.244.1.5:5000",
			[]string{"6.6.6.6, 198.51.100.1, 203.0.113.50"}, "198.51.100.1"},
		{"two proxies across two headers", 2, nil, "10.244.1.5:5000",
			[]string{"198.51.100.1", "203.0.113.50"}, "198.51.100.1"},
		{"short chain: left-most entry", 3, nil, "10.244.1.5:5000", []string{"198.51.100.1, 203.0.113.50"}, "198.51.100.1"},
		{"no XFF: the peer", 1, nil, "10.244.1.5:5000", nil, "10.244.1.5"},
		{"malformed hop: the peer", 1, nil, "10.244.1.5:5000", []string{"198.51.100.1, nonsense"}, "10.244.1.5"},
		{"empty hop: the peer", 1, nil, "10.244.1.5:5000", []string{"198.51.100.1,"}, "10.244.1.5"},
		{"IPv4-mapped hop is unmapped", 1, nil, "10.244.1.5:5000", []string{"::ffff:198.51.100.1"}, "198.51.100.1"},
		{"CIDRs still gate the peer", 1, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			"203.0.113.9:5000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"CIDRs gate, hops pick", 2, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			"10.244.1.5:5000", []string{"198.51.100.1, 203.0.113.50"}, "198.51.100.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			policy := api.ClientIPPolicy{TrustedProxies: tt.trust, TrustedHops: tt.hops}
			is.Equal(api.NewClientIPResolver(policy).ClientIP(r), tt.want)
		})
	}
}

// TestClientIPHeader covers CLIENT_IP_HEADER (ocidex-w6st): the edge's header
// wins over X-Forwarded-For and TRUSTED_PROXY_HOPS, falls back to the peer
// when absent or unparseable, and still answers to TRUSTED_PROXY_CIDRS.
func TestClientIPHeader(t *testing.T) {
	tests := []struct {
		name   string
		trust  []netip.Prefix
		remote string
		header string
		want   string
	}{
		{"header is the client", nil, "10.244.1.5:5000", "198.51.100.1", "198.51.100.1"},
		{"IPv6 header", nil, "10.244.1.5:5000", "2001:db8::1", "2001:db8::1"},
		{"missing header: the peer", nil, "10.244.1.5:5000", "", "10.244.1.5"},
		{"garbage header: the peer", nil, "10.244.1.5:5000", "198.51.100.1, 6.6.6.6", "10.244.1.5"},
		{"untrusted peer's header is ignored", []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			"203.0.113.9:5000", "198.51.100.1", "203.0.113.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
			r.RemoteAddr = tt.remote
			r.Header.Set("X-Forwarded-For", "6.6.6.6")
			if tt.header != "" {
				r.Header.Set("CF-Connecting-IP", tt.header)
			}
			policy := api.ClientIPPolicy{TrustedProxies: tt.trust, TrustedHops: 1, Header: "CF-Connecting-IP"}
			is.Equal(api.NewClientIPResolver(policy).ClientIP(r), tt.want)
		})
	}
}

func newRateLimitedRouter(limit int, trusted []netip.Prefix) http.Handler {
	h := api.NewHandler(nil, nil, &fakeAuthService{}, nil, nil, nil, nil, nil, nil, nil, &fakePinger{}, nil,
		&config.Config{
			Environment:    "development",
			SessionSecret:  strings.Repeat("k", 32),
			FrontendURL:    "http://localhost:3000",
			AuthRateLimit:  limit,
			TrustedProxies: trusted,
		})
	return api.NewRouter(h, "*", "", "")
}

func loginFrom(router http.Handler, remote, xff string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestAuthRateLimit(t *testing.T) {
	is := is.New(t)
	router := newRateLimitedRouter(3, nil)

	for range 3 {
		is.True(loginFrom(router, "203.0.113.9:1", "").Code != http.StatusTooManyRequests)
	}
	w := loginFrom(router, "203.0.113.9:1", "")
	is.Equal(w.Code, http.StatusTooManyRequests)
	is.True(w.Header().Get("Retry-After") != "")
	is.Equal(w.Header().Get("Content-Type"), "application/problem+json")

	// Another client has its own budget.
	is.True(loginFrom(router, "203.0.113.10:1", "").Code != http.StatusTooManyRequests)

	// Spoofing X-Forwarded-For from an untrusted peer does not buy a new one.
	is.Equal(loginFrom(router, "203.0.113.9:1", "198.51.100.77").Code, http.StatusTooManyRequests)
}

func TestAuthRateLimitBehindTrustedProxy(t *testing.T) {
	is := is.New(t)
	router := newRateLimitedRouter(1, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	is.True(loginFrom(router, "10.0.0.2:1", "198.51.100.1").Code != http.StatusTooManyRequests)
	is.Equal(loginFrom(router, "10.0.0.2:1", "198.51.100.1").Code, http.StatusTooManyRequests)
	// Same proxy, different client: keyed by the client, not the proxy.
	is.True(loginFrom(router, "10.0.0.2:1", "198.51.100.2").Code != http.StatusTooManyRequests)
}

func TestAuthRateLimitZeroDisables(t *testing.T) {
	is := is.New(t)
	router := newRateLimitedRouter(0, nil)
	for range 50 {
		is.True(loginFrom(router, "203.0.113.9:1", "").Code != http.StatusTooManyRequests)
	}
}

func newAPILimitedRouter(ingest, heavy int) http.Handler {
	authSvc := &fakeAuthService{users: map[string]service.AuthUser{
		"alice": {ID: ownerUUID, Role: "member"},
		"bob":   {ID: otherUUID, Role: "member"},
	}}
	h := api.NewHandler(nil, nil, authSvc, nil, nil, nil, nil, nil, nil, nil, &fakePinger{}, nil,
		&config.Config{
			Environment:        "development",
			SessionSecret:      strings.Repeat("k", 32),
			APIRateLimitIngest: ingest,
			APIRateLimitHeavy:  heavy,
		})
	return api.NewRouter(h, "*", "", "")
}

func requestAs(router http.Handler, method, path, token, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = remote
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

// TestHeavyRateLimitIsPerPrincipal checks the heavy-read budget is one per
// principal, shared across the operations that carry it, and answered with a
// problem document.
func TestHeavyRateLimitIsPerPrincipal(t *testing.T) {
	is := is.New(t)
	router := newAPILimitedRouter(0, 2)
	const versions = "/api/v1/components/versions?name=x"
	changelog := "/api/v1/artifacts/" + testRegistryID + "/changelog"

	is.True(requestAs(router, http.MethodGet, versions, "alice", "203.0.113.9:1").Code != http.StatusTooManyRequests)
	is.True(requestAs(router, http.MethodGet, changelog, "alice", "203.0.113.9:1").Code != http.StatusTooManyRequests)
	w := requestAs(router, http.MethodGet, versions, "alice", "198.51.100.1:1") // a new address does not help
	is.Equal(w.Code, http.StatusTooManyRequests)
	is.Equal(w.Header().Get("Content-Type"), "application/problem+json")
	is.True(w.Header().Get("Retry-After") != "")

	// Another user from the same address has a budget of their own.
	is.True(requestAs(router, http.MethodGet, versions, "bob", "203.0.113.9:1").Code != http.StatusTooManyRequests)

	// Anonymous callers are keyed by address.
	is.True(requestAs(router, http.MethodGet, versions, "", "203.0.113.50:1").Code != http.StatusTooManyRequests)
	is.True(requestAs(router, http.MethodGet, versions, "", "203.0.113.50:1").Code != http.StatusTooManyRequests)
	is.Equal(requestAs(router, http.MethodGet, versions, "", "203.0.113.50:1").Code, http.StatusTooManyRequests)
	is.True(requestAs(router, http.MethodGet, versions, "", "203.0.113.51:1").Code != http.StatusTooManyRequests)
}

func TestIngestRateLimit(t *testing.T) {
	is := is.New(t)
	router := newAPILimitedRouter(1, 0)

	is.True(requestAs(router, http.MethodPost, "/api/v1/sboms", "alice", "203.0.113.9:1").Code != http.StatusTooManyRequests)
	is.Equal(requestAs(router, http.MethodPost, "/api/v1/sboms", "alice", "203.0.113.9:1").Code, http.StatusTooManyRequests)
	is.True(requestAs(router, http.MethodPost, "/api/v1/sboms", "bob", "203.0.113.9:1").Code != http.StatusTooManyRequests)

	// The heavy limit is disabled at 0, and ingest's budget is its own.
	for range 5 {
		is.True(requestAs(router, http.MethodGet, "/api/v1/components/versions?name=x", "alice", "203.0.113.9:1").Code !=
			http.StatusTooManyRequests)
	}
}
