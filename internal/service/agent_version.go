package service

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
)

// AgentVersionSkew describes how far an agent's version is from the server's,
// or returns "" when there is nothing worth saying: the versions agree on
// major.minor, or either one is not a release version (a dev build, a commit
// hash) and so cannot be compared.
//
// The agent and the server ship from one repo and one release, so any minor
// difference is skew. It is a warning, never a rejection: the inventory
// contract is backward compatible, and refusing a snapshot over a version
// string would turn an upgrade-ordering detail into lost inventory.
func AgentVersionSkew(agentVersion, serverVersion string) string {
	a, errA := semver.NewVersion(agentVersion)
	s, errS := semver.NewVersion(serverVersion)
	if errA != nil || errS != nil {
		return ""
	}
	if a.Major() == s.Major() && a.Minor() == s.Minor() {
		return ""
	}
	if a.GreaterThan(s) {
		return fmt.Sprintf("agent %s is newer than server %s; pin the agent chart to the server's version", a.Original(), s.Original())
	}
	return fmt.Sprintf("agent %s is older than server %s; upgrade the agent chart to match", a.Original(), s.Original())
}
