package netguard_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/netguard"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	p, err := netguard.ParsePrefixes(cidrs)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheck(t *testing.T) {
	allowPrivate := netguard.Policy{AllowPrivate: true}
	tests := []struct {
		name   string
		policy netguard.Policy
		ip     string
		denied bool
	}{
		{name: "public v4", ip: "93.184.216.34"},
		{name: "public v6", ip: "2606:2800:220:1:248:1893:25c8:1946"},

		{name: "loopback", ip: "127.0.0.1", denied: true},
		{name: "loopback range", ip: "127.255.0.9", denied: true},
		{name: "loopback v6", ip: "::1", denied: true},
		{name: "unspecified v4", ip: "0.0.0.0", denied: true},
		{name: "this network", ip: "0.1.2.3", denied: true},
		{name: "unspecified v6", ip: "::", denied: true},
		{name: "cloud metadata", ip: "169.254.169.254", denied: true},
		{name: "link-local v6", ip: "fe80::1", denied: true},
		{name: "multicast v4", ip: "239.1.1.1", denied: true},
		{name: "multicast v6", ip: "ff02::1", denied: true},
		{name: "broadcast", ip: "255.255.255.255", denied: true},
		{name: "mapped loopback", ip: "::ffff:127.0.0.1", denied: true},
		{name: "mapped metadata", ip: "::ffff:169.254.169.254", denied: true},

		{name: "always-denied ignores AllowPrivate", policy: allowPrivate, ip: "127.0.0.1", denied: true},

		{name: "10/8", ip: "10.1.2.3", denied: true},
		{name: "172.16/12", ip: "172.31.0.1", denied: true},
		{name: "192.168/16", ip: "192.168.1.1", denied: true},
		{name: "CGNAT", ip: "100.64.0.1", denied: true},
		{name: "ULA", ip: "fd00::1", denied: true},
		{name: "mapped private", ip: "::ffff:10.0.0.1", denied: true},
		{name: "172.32 is public", ip: "172.32.0.1"},

		{name: "10/8 with AllowPrivate", policy: allowPrivate, ip: "10.1.2.3"},
		{name: "192.168/16 with AllowPrivate", policy: allowPrivate, ip: "192.168.1.1"},
		{name: "CGNAT with AllowPrivate", policy: allowPrivate, ip: "100.64.0.1"},
		{name: "ULA with AllowPrivate", policy: allowPrivate, ip: "fd00::1"},

		{name: "allow-list opens loopback", policy: netguard.Policy{AllowCIDRs: prefixes(t, "127.0.0.0/8")}, ip: "127.0.0.1"},
		{name: "allow-list opens one private host", policy: netguard.Policy{AllowCIDRs: prefixes(t, "10.0.0.5")}, ip: "10.0.0.5"},
		{name: "allow-list is narrow", policy: netguard.Policy{AllowCIDRs: prefixes(t, "10.0.0.5")}, ip: "10.0.0.6", denied: true},
		{name: "allow-list beats deny-list", policy: netguard.Policy{AllowCIDRs: prefixes(t, "8.8.8.8"), DenyCIDRs: prefixes(t, "8.8.0.0/16")}, ip: "8.8.8.8"},
		{name: "deny-list", policy: netguard.Policy{DenyCIDRs: prefixes(t, "8.8.0.0/16")}, ip: "8.8.4.4", denied: true},
		{name: "deny-list beats AllowPrivate", policy: netguard.Policy{AllowPrivate: true, DenyCIDRs: prefixes(t, "10.0.0.0/8")}, ip: "10.0.0.1", denied: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			err := tt.policy.Check(netip.MustParseAddr(tt.ip))
			if tt.denied {
				is.True(errors.Is(err, netguard.ErrDenied))
				return
			}
			is.NoErr(err)
		})
	}
}

func TestControl(t *testing.T) {
	is := is.New(t)
	var p netguard.Policy
	is.True(errors.Is(p.Control("tcp", "127.0.0.1:80", nil), netguard.ErrDenied))
	is.True(errors.Is(p.Control("tcp6", "[::ffff:127.0.0.1]:80", nil), netguard.ErrDenied))
	is.True(errors.Is(p.Control("tcp", "garbage", nil), netguard.ErrDenied))
	is.NoErr(p.Control("tcp", "93.184.216.34:443", nil))
}

// TestTransport proves the guard runs on the dial, against a real listener on
// loopback.
func TestTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	t.Run("loopback refused", func(t *testing.T) {
		is := is.New(t)
		client := &http.Client{Transport: netguard.Policy{}.Transport()}
		resp, err := client.Get(srv.URL) //nolint:noctx // test
		if err == nil {
			resp.Body.Close()
		}
		is.True(errors.Is(err, netguard.ErrDenied))
	})
	t.Run("loopback allowed by CIDR", func(t *testing.T) {
		is := is.New(t)
		client := &http.Client{Transport: netguard.Policy{AllowCIDRs: prefixes(t, "127.0.0.0/8")}.Transport()}
		resp, err := client.Get(srv.URL) //nolint:noctx // test
		is.NoErr(err)
		resp.Body.Close()
		is.Equal(resp.StatusCode, http.StatusNoContent)
	})
}

func TestParsePrefixes(t *testing.T) {
	is := is.New(t)
	got, err := netguard.ParsePrefixes([]string{"10.0.0.0/8", "", "192.168.1.7", "fd00::/8"})
	is.NoErr(err)
	is.Equal(len(got), 3)
	is.Equal(got[1], netip.MustParsePrefix("192.168.1.7/32"))

	_, err = netguard.ParsePrefixes([]string{"10.0.0.0/33"})
	is.True(err != nil)
	_, err = netguard.ParsePrefixes([]string{"not-an-ip"})
	is.True(err != nil)
}
