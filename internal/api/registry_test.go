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
