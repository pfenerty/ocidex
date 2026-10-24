package service

import (
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestRetentionPolicyValidate(t *testing.T) {
	tests := []struct {
		name   string
		policy RetentionPolicy
		ok     bool
	}{
		{"off", RetentionPolicy{}, true},
		{"window only", RetentionPolicy{RegistryWindow: true}, true},
		{"floor", RetentionPolicy{KeepLast: 2}, true},
		{"with age", RetentionPolicy{KeepLast: 20, MaxAge: 90 * 24 * time.Hour}, true},
		{"one is below the floor", RetentionPolicy{KeepLast: 1}, false},
		{"negative keep_last", RetentionPolicy{KeepLast: -1}, false},
		{"negative age", RetentionPolicy{KeepLast: 2, MaxAge: -time.Hour}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(tt.policy.Validate() == nil, tt.ok)
		})
	}
}

func TestRowLimit(t *testing.T) {
	is := is.New(t)
	is.Equal(rowLimit(50), int32(50))
	is.Equal(rowLimit(0), int32(2147483647))
	is.Equal(rowLimit(-1), int32(2147483647))
}
