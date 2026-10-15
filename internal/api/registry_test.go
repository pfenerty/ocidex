package api

import (
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/netguard"
)

func TestValidateVerificationConfig_KeylessRequiresIdentityAndIssuer(t *testing.T) {
	is := is.New(t)
	identity := "^https://github.com/example/repo/.*$"
	issuer := "https://token.actions.githubusercontent.com"
	empty := ""

	is.NoErr(validateVerificationConfig("keyless", nil, &identity, &issuer))
	is.True(validateVerificationConfig("keyless", nil, nil, &issuer) != nil)
	is.True(validateVerificationConfig("keyless", nil, &identity, nil) != nil)
	is.True(validateVerificationConfig("keyless", nil, &empty, &issuer) != nil)
	is.True(validateVerificationConfig("keyless", nil, &identity, &empty) != nil)
}

func TestValidateVerificationConfig_PublicKeyRequiresTrustPublicKey(t *testing.T) {
	is := is.New(t)
	key := "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----"
	empty := ""

	is.NoErr(validateVerificationConfig("public_key", &key, nil, nil))
	is.True(validateVerificationConfig("public_key", nil, nil, nil) != nil)
	is.True(validateVerificationConfig("public_key", &empty, nil, nil) != nil)
}

func TestValidateVerificationConfig_OtherModesUnaffected(t *testing.T) {
	is := is.New(t)

	is.NoErr(validateVerificationConfig("none", nil, nil, nil))
	is.NoErr(validateVerificationConfig("", nil, nil, nil))
}

func TestValidateRegistryURL(t *testing.T) {
	loopback := netguard.Policy{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	tests := []struct {
		name     string
		url      string
		insecure bool
		egress   netguard.Policy
		wantErr  bool
	}{
		{name: "host", url: "registry.example.com"},
		{name: "host:port", url: "registry.example.com:5000"},
		{name: "https scheme", url: "https://registry.example.com"},
		{name: "trailing slash", url: "https://registry.example.com/"},
		{name: "http with insecure", url: "http://zot:5000", insecure: true},
		{name: "public IP", url: "93.184.216.34:5000"},
		{name: "http without insecure", url: "http://registry.example.com", wantErr: true},
		{name: "userinfo", url: "https://user:pass@registry.example.com", wantErr: true},
		{name: "query", url: "registry.example.com?x=1", wantErr: true},
		{name: "fragment", url: "registry.example.com#frag", wantErr: true},
		{name: "path", url: "registry.example.com/team", wantErr: true},
		{name: "file scheme", url: "file:///etc/passwd", wantErr: true},
		{name: "no host", url: "https://:5000", wantErr: true},
		{name: "non-numeric port", url: "registry.example.com:abc", wantErr: true},
		{name: "cloud metadata", url: "169.254.169.254", wantErr: true},
		{name: "loopback refused", url: "127.0.0.1:5000", wantErr: true},
		{name: "loopback allowed", url: "127.0.0.1:5000", egress: loopback},
		{name: "IPv6 loopback", url: "[::1]:5000", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			err := validateRegistryURL(tt.url, tt.insecure, tt.egress)
			if !tt.wantErr {
				is.NoErr(err)
				return
			}
			var se huma.StatusError
			is.True(errors.As(err, &se))
			is.Equal(se.GetStatus(), http.StatusUnprocessableEntity)
		})
	}
}
