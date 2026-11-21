package service

import (
	"testing"

	"github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/repository"
)

// The keys are pinned, not recomputed: a change to LockKey or to a name would
// make a mid-rollout fleet contend for two different locks and elect two
// leaders. These are the values the hand-rolled derivations produced.
func TestLockKeyValuesArePinned(t *testing.T) {
	tests := []struct {
		name string
		want int64
	}{
		{PollerLockName, -3962425637078599556},
		{ReverifierLockName, 6502743068727568081},
		{RetentionLockName, 4659009584415815708},
		{VulnRefreshLockName, 933876737202717523},
		{repository.RollupRefreshLockName, 4759493367209702470},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			is.Equal(LockKey(tt.name), tt.want)
		})
	}
}
