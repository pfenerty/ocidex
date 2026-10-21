// Package netguard decides which addresses OCIDex may open outbound connections
// to on behalf of a user.
//
// Registry URLs are user-supplied, and the API, scanner worker and enrichers all
// dial them. Without a guard any user who can create a registry can make those
// processes reach loopback, the cluster network or a cloud metadata endpoint.
// The check runs in net.Dialer.Control, on the IP actually being connected to,
// so neither DNS rebinding nor a redirect to an internal host gets around it.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/pfenerty/ocidex/internal/tracing"
)

// ErrDenied is wrapped by every refusal, so a caller can classify it as a
// permanent failure rather than one worth retrying.
var ErrDenied = errors.New("egress denied")

// alwaysDenied are never reachable unless an AllowCIDRs entry names them.
var alwaysDenied = mustPrefixes(
	"0.0.0.0/8",      // "this network", including the unspecified address
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local, including cloud metadata at 169.254.169.254
	"224.0.0.0/4",    // multicast
	"255.255.255.255/32",
	"::/128", // unspecified
	"::1/128",
	"fe80::/10", // link-local
	"ff00::/8",  // multicast
)

// private are denied unless AllowPrivate is set or an AllowCIDRs entry names
// them. Many installations scan a registry inside their own cluster, which is
// why this half is configurable and alwaysDenied is not.
var private = mustPrefixes(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10", // CGNAT
	"fc00::/7",      // unique local
)

// Policy is an egress address policy. The zero value denies loopback,
// link-local, multicast and private addresses and allows everything else.
type Policy struct {
	// AllowCIDRs are reachable regardless of any other rule, including the
	// always-denied ranges. It is the only way to reach those.
	AllowCIDRs []netip.Prefix
	// DenyCIDRs are refused in addition to the built-in ranges.
	DenyCIDRs []netip.Prefix
	// AllowPrivate admits RFC 1918, CGNAT and unique-local IPv6 addresses.
	AllowPrivate bool
}

// Check reports whether ip may be dialed, returning an error wrapping
// ErrDenied if not. An IPv4-mapped IPv6 address is judged as the IPv4 address
// it carries.
func (p Policy) Check(ip netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrDenied)
	}
	if contains(p.AllowCIDRs, ip) {
		return nil
	}
	if contains(alwaysDenied, ip) || contains(p.DenyCIDRs, ip) {
		return fmt.Errorf("%w: %s", ErrDenied, ip)
	}
	if !p.AllowPrivate && contains(private, ip) {
		return fmt.Errorf("%w: %s is a private address", ErrDenied, ip)
	}
	return nil
}

// Control is a net.Dialer.Control function. It runs after name resolution, on
// the address each connection attempt is about to use.
func (p Policy) Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: unparseable address %q", ErrDenied, address)
	}
	return p.Check(ap.Addr())
}

// Dialer returns a net.Dialer that enforces the policy, with the same timeouts
// as http.DefaultTransport's.
func (p Policy) Dialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   p.Control,
	}
}

// DialContext dials through a guarded Dialer.
func (p Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return p.Dialer().DialContext(ctx, network, address)
}

// Transport returns a clone of http.DefaultTransport whose connections are
// guarded.
//
// Proxy is kept from the default (HTTP_PROXY and friends). A request sent
// through a proxy dials the proxy, not the target, so the guard then judges the
// proxy's address and the proxy is trusted to apply its own egress rules.
func (p Policy) Transport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = p.DialContext
	return t
}

// RoundTripper is Transport with a client span per request (ADR-0055 T2).
// Use it for outbound clients; keep Transport where a caller needs the
// concrete *http.Transport.
func (p Policy) RoundTripper() http.RoundTripper {
	return tracing.Transport(p.Transport())
}

// ParsePrefixes parses CIDRs, accepting a bare address as a single-host prefix.
// Blank entries are skipped.
func ParsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range cidrs {
		if c == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			addr, addrErr := netip.ParseAddr(c)
			if addrErr != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", c, err)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out, err := ParsePrefixes(cidrs)
	if err != nil {
		panic(err)
	}
	return out
}
