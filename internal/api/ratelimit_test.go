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
			is.Equal(api.NewClientIPResolver(tt.trusted).ClientIP(r), tt.want)
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
