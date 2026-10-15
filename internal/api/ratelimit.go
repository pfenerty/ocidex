package api

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/httprate"

	"github.com/pfenerty/ocidex/internal/config"
)

// ClientIPResolver answers "which client sent this request" for rate limiting
// (ocidex-mqav.5).
//
// X-Forwarded-For is a header any client can write, so it is believed only
// when the direct peer is a trusted proxy, and then only as far as the chain
// stays inside trusted proxies: the right-most hop that is not one of them is
// the client. chi's middleware.RealIP is deliberately not used — it believes
// the header from anyone, which would let a client pick its own rate-limit
// key.
type ClientIPResolver struct {
	trusted []netip.Prefix
}

// NewClientIPResolver returns a resolver that believes X-Forwarded-For only
// from peers inside trusted. With no trusted prefixes the direct peer is
// always the client.
func NewClientIPResolver(trusted []netip.Prefix) *ClientIPResolver {
	return &ClientIPResolver{trusted: trusted}
}

// ClientIP returns the request's client IP as a string.
func (c *ClientIPResolver) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	client := peer.Unmap()
	if !c.isTrusted(client) {
		return client.String()
	}

	// Several X-Forwarded-For headers are one list in order (RFC 7230 §3.2.2).
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// A hop a trusted proxy would not have written: stop at the last
			// address the chain vouched for rather than guess past it.
			break
		}
		client = hop.Unmap()
		if !c.isTrusted(client) {
			break
		}
	}
	return client.String()
}

func (c *ClientIPResolver) isTrusted(ip netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// rateLimiter is one fixed-window-per-key limit, usable as chi middleware on
// raw routes and as huma middleware on registered operations. A nil
// *rateLimiter is a disabled limit and passes everything.
type rateLimiter struct {
	rl     *httprate.RateLimiter
	key    func(*http.Request) string
	detail string
}

// newRateLimiter returns a limit of perMinute requests per key, or nil when
// perMinute is 0 or less. detail is the 429 problem document's detail.
func newRateLimiter(perMinute int, key func(*http.Request) string, detail string) *rateLimiter {
	if perMinute <= 0 {
		return nil
	}
	return &rateLimiter{
		rl:     httprate.NewRateLimiter(perMinute, time.Minute),
		key:    key,
		detail: detail,
	}
}

// Middleware is the chi form. A limited request gets 429 with Retry-After and
// an RFC 7807 body.
func (l *rateLimiter) Middleware(next http.Handler) http.Handler {
	if l == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if l.rl.OnLimit(w, r, l.key(r)) {
			writeProblem(w, http.StatusTooManyRequests, l.detail)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Huma is the huma form, for limits on registered operations. It answers 429
// through huma.WriteErr so the body matches every other API error.
func (l *rateLimiter) Huma(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if l == nil {
			next(ctx)
			return
		}
		r, w := humachi.Unwrap(ctx)
		if l.rl.OnLimit(w, r, l.key(r)) {
			_ = huma.WriteErr(api, ctx, http.StatusTooManyRequests, l.detail)
			return
		}
		next(ctx)
	}
}

// principalKey keys a per-principal limit: the user for an authenticated
// request, so one account's budget follows it across addresses and an office
// behind one NAT does not share one, and the client IP otherwise. The prefixes
// keep a user ID from ever colliding with an address.
func (h *Handler) principalKey(r *http.Request) string {
	if user, ok := UserFromContext(r.Context()); ok {
		return "user:" + uuidToStr(user.ID)
	}
	return "ip:" + h.clientIPs.ClientIP(r)
}

// buildAPIRateLimits builds the per-principal limits on the endpoints that
// cost the most to serve (ocidex-mqav.6): SBOM ingest, and the heavy
// artifact/component reads. Each is one budget shared by every operation that
// carries it. Without a config both are disabled.
func (h *Handler) buildAPIRateLimits() {
	cfg := h.cfg
	if cfg == nil {
		cfg = &config.Config{}
	}
	h.ingestLimit = newRateLimiter(cfg.APIRateLimitIngest, h.principalKey,
		"SBOM ingest rate limit exceeded; retry later")
	h.heavyLimit = newRateLimiter(cfg.APIRateLimitHeavy, h.principalKey,
		"rate limit for expensive queries exceeded; retry later")
}
