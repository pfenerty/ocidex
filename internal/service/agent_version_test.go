package service

import (
	"testing"

	"github.com/matryer/is"
)

func TestAgentVersionSkew(t *testing.T) {
	tests := []struct {
		name, agent, server string
		want                string
	}{
		{"same", "v1.1.0", "1.1.3", ""},
		{"dev agent", "dev", "1.1.0", ""},
		{"dev server", "1.1.0", "dev", ""},
		{"not reported", "", "1.1.0", ""},
		{"older", "v1.0.2", "v1.1.0", "agent v1.0.2 is older than server v1.1.0; upgrade the agent chart to match"},
		{"newer", "2.0.0", "1.1.0", "agent 2.0.0 is newer than server 1.1.0; pin the agent chart to the server's version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is.New(t).Equal(AgentVersionSkew(tt.agent, tt.server), tt.want)
		})
	}
}
