// Command mock-idp runs a mock OpenID Connect issuer for local development.
//
// It is a development tool and must never be built into a production image:
// it signs with an ephemeral key, accepts any client_id, and issues a token
// for whoever the request names. scripts/dev-auth.sh starts it and points the
// API's OIDC_ISSUER_URL at it, which is what puts the /auth/login and
// /auth/callback routes under a real protocol exchange instead of leaving them
// unexercised.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pfenerty/ocidex/internal/devidp"
)

func main() {
	addr := flag.String("addr", ":9999", "listen address")
	issuer := flag.String("issuer", "", "issuer URL as clients configure it (default http://127.0.0.1<addr>)")
	personas := flag.String("personas", "devadmin,devowner,devsecurity,devviewer,devoutsider,devdeveloper",
		"comma-separated names offered by the sign-in picker; any subject is accepted regardless")
	flag.Parse()

	issuerURL := *issuer
	if issuerURL == "" {
		issuerURL = "http://127.0.0.1" + *addr
	}

	srv, err := devidp.New(issuerURL, strings.Split(*personas, ","))
	if err != nil {
		log.Printf("mock-idp: %v", err)
		os.Exit(1)
	}

	fmt.Printf("mock-idp listening on %s as %s\n", *addr, issuerURL) //nolint:forbidigo // dev tool banner

	// Timeouts are here only so the linter's slowloris rule is satisfied; a
	// dev-only listener has nothing to defend.
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Printf("mock-idp: %v", err)
		os.Exit(1)
	}
}
