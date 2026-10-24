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

// ClientIPPolicy says how far to believe what proxies report about the client
// (ocidex-mqav.5, ocidex-w6st).
//
// Precedence, strictest gate first:
//
//  1. TrustedProxies, when set, gates everything: a direct peer outside them
//     is the client, whatever headers it sent.
//  2. Header, when set, names a header the edge overwrites (CF-Connecting-IP,
//     True-Client-IP); its value is the client.
//  3. Otherwise TrustedHops, when set, is how many proxies stand in front of
//     the API: the client is the TrustedHops-th X-Forwarded-For entry from the
//     right, Envoy's xff_num_trusted_hops.
//  4. Otherwise the X-Forwarded-For chain is walked right to left while it
//     stays inside TrustedProxies.
//
// Header and TrustedHops describe topology rather than addresses, so they are
// only as good as the claim that every path to the API passes through those
// proxies. TrustedProxies is the one option a client cannot route around.
type ClientIPPolicy struct {
	TrustedProxies []netip.Prefix
	TrustedHops    int
	Header         string
}

// ClientIPResolver answers "which client sent this request" for rate limiting.
//
// X-Forwarded-For is a header any client can write, so it is believed only
// as far as ClientIPPolicy says. chi's middleware.RealIP is deliberately not
// used — it believes the header from anyone, which would let a client pick
// its own rate-limit key.
type ClientIPResolver struct {
	policy ClientIPPolicy
}

// NewClientIPResolver returns a resolver for policy. The zero policy trusts
// no proxy: the direct peer is always the client.
func NewClientIPResolver(policy ClientIPPolicy) *ClientIPResolver {
	return &ClientIPResolver{policy: policy}
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
	peer = peer.Unmap()
	if len(c.policy.TrustedProxies) > 0 && !c.isTrusted(peer) {
		return peer.String()
	}
	switch {
	case c.policy.Header != "":
		return c.fromHeader(r, peer).String()
	case c.policy.TrustedHops > 0:
		return c.fromHops(forwardedFor(r), peer).String()
	case len(c.policy.TrustedProxies) > 0:
		return c.fromTrustedChain(forwardedFor(r), peer).String()
	}
	return peer.String()
}

// forwardedFor is the X-Forwarded-For chain. Several headers are one list in
// order (RFC 7230 §3.2.2).
func forwardedFor(r *http.Request) []string {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return nil
	}
	return strings.Split(strings.Join(values, ","), ",")
}

// fromHeader reads the edge's client header. A missing or unparseable value
// means the request did not come through the edge that sets it, so the peer
// is the client.
func (c *ClientIPResolver) fromHeader(r *http.Request, peer netip.Addr) netip.Addr {
	ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(c.policy.Header)))
	if err != nil {
		return peer
	}
	return ip.Unmap()
}

// fromHops picks the TrustedHops-th entry from the right. A chain shorter than
// that has no entry a client could have prepended beyond what the proxies
// wrote, so its left-most entry is the client. A hop that does not parse was
// not written by a proxy, and the peer is the client.
func (c *ClientIPResolver) fromHops(hops []string, peer netip.Addr) netip.Addr {
	if len(hops) == 0 {
		return peer
	}
	i := len(hops) - c.policy.TrustedHops
	if i < 0 {
		i = 0
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
	if err != nil {
		return peer
	}
	return ip.Unmap()
}

// fromTrustedChain walks the chain right to left while it stays inside
// TrustedProxies: the right-most hop that is not one of them is the client.
func (c *ClientIPResolver) fromTrustedChain(hops []string, peer netip.Addr) netip.Addr {
	client := peer
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
	return client
}

func (c *ClientIPResolver) isTrusted(ip netip.Addr) bool {
	for _, p := range c.policy.TrustedProxies {
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
