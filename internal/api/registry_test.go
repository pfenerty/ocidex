package api

import (
	"testing"

	"github.com/matryer/is"
)

func TestValidateVerificationConfig_KeylessRequiresIdentityAndIssuer(t *testing.T) {
	is := is.New(t)
	identity := "^https://github.com/example/repo/.*$"
	issuer := "https://token.actions.githubusercontent.com"
	empty := ""

	is.NoErr(validateVerificationConfig("keyless", &identity, &issuer))
	is.True(validateVerificationConfig("keyless", nil, &issuer) != nil)
	is.True(validateVerificationConfig("keyless", &identity, nil) != nil)
	is.True(validateVerificationConfig("keyless", &empty, &issuer) != nil)
	is.True(validateVerificationConfig("keyless", &identity, &empty) != nil)
}

func TestValidateVerificationConfig_OtherModesUnaffected(t *testing.T) {
	is := is.New(t)

	is.NoErr(validateVerificationConfig("none", nil, nil))
	is.NoErr(validateVerificationConfig("public_key", nil, nil))
	is.NoErr(validateVerificationConfig("", nil, nil))
}
