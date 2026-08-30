// Package auth holds the identity providers OCIDex can authenticate against.
//
// It exists so that the service layer never names an issuer. Before
// ocidex-iqkt, "who is signed in" was spelled github_id/github_username and
// reached from the database schema up through the frontend; adding a second
// issuer meant editing every one of those layers. Here a sign-in is a Provider
// returning an Identity, and everything above it is issuer-agnostic.
package auth

import "context"

// Identity is what a provider knows about the person who just signed in.
//
// Provider and Subject together are the account's key — they are what
// user_identity is unique on — and neither is ever shown to a user. Email and
// DisplayName are cosmetic and may be empty: an issuer is free not to release
// them, and an account with neither is still a valid account.
type Identity struct {
	// Provider is the issuer key, matching Provider.Name and the
	// user_identity.provider column: "github", or "oidc:<name>".
	Provider string
	// Subject is the issuer's stable identifier for this person. It must not
	// change when they rename themselves or change their email, which is why
	// GitHub's numeric id is used here rather than their login.
	Subject string
	// Email is the address the issuer released, if any. Advisory only: it is
	// never used to match an existing account, because an issuer that does not
	// verify email addresses would otherwise be able to take over one.
	Email string
	// DisplayName is what to call this person in the UI. Empty is allowed;
	// callers fall back to something they can derive themselves.
	DisplayName string
}

// Provider is one configured identity source.
//
// The verifier threaded through AuthURL and Exchange is a PKCE code verifier.
// It is generated per sign-in attempt and carried in the signed state cookie,
// so a provider that does not use PKCE simply ignores it — that is what the
// GitHub provider does, and it keeps the OIDC provider in ocidex-iqkt.3 an
// addition rather than a change to this interface.
type Provider interface {
	// Name is the issuer key stored in user_identity.provider. It is stable:
	// changing it orphans every account that signed in through this provider.
	Name() string
	// AuthURL is where to send the browser to begin a sign-in.
	AuthURL(state, verifier string) string
	// Exchange redeems the callback's authorization code for an Identity.
	Exchange(ctx context.Context, code, verifier string) (Identity, error)
}
