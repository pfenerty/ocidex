package api

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/matryer/is"
)

func TestDeriveFrontendURL(t *testing.T) {
	const configured = "https://ocidex.example:3000"

	tests := []struct {
		name    string
		env     string
		host    string
		tls     bool
		xfp     string
		allowed []string
		want    string
	}{
		{
			name: "production ignores Host and TLS",
			env:  envProduction, host: "evil.example", allowed: []string{"http://evil.example:3000"},
			want: configured,
		},
		{
			name: "production with no TLS still keeps the configured https",
			env:  envProduction, host: "ocidex.example",
			want: configured,
		},
		{
			name: "development follows an allowed host",
			env:  envDevelopment, host: "100.64.0.7:8080", allowed: []string{"http://100.64.0.7:3000"},
			want: "http://100.64.0.7:3000",
		},
		{
			name: "development with TLS follows an allowed https host",
			env:  envDevelopment, host: "dev.example", tls: true, allowed: []string{"https://dev.example:3000"},
			want: "https://dev.example:3000",
		},
		{
			name: "development foreign Host falls back",
			env:  envDevelopment, host: "evil.example", allowed: []string{"http://localhost:3000"},
			want: configured,
		},
		{
			name: "development wildcard does not admit a foreign Host",
			env:  envDevelopment, host: "evil.example", allowed: []string{"*"},
			want: configured,
		},
		{
			name: "X-Forwarded-Proto is not trusted",
			env:  envDevelopment, host: "localhost", xfp: "https", allowed: []string{"https://localhost:3000"},
			want: configured,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			r := httptest.NewRequest("GET", "/auth/login", nil)
			r.Host = tt.host
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if tt.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", tt.xfp)
			}
			is.Equal(deriveFrontendURL(r, configured, tt.env, tt.allowed), tt.want)
		})
	}
}
