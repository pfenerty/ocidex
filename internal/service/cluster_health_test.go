package service

import (
	"testing"
	"time"

	"github.com/matryer/is"
)

func TestClusterHealth(t *testing.T) {
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	secs := func(n int32) *AgentInfo { return &AgentInfo{ReportIntervalSeconds: &n} }

	tests := []struct {
		name    string
		cluster Cluster
		want    string
	}{
		{"never reported", Cluster{}, HealthNeverReported},
		{"only rejections", Cluster{LastPushErrorAt: ago(time.Minute), LastPushError: "bad key"}, HealthErroring},
		{"healthy at default interval", Cluster{LastSeenAt: ago(10 * time.Minute)}, HealthHealthy},
		{"stale at default interval", Cluster{LastSeenAt: ago(16 * time.Minute)}, HealthStale},
		{"reported interval widens the window", Cluster{LastSeenAt: ago(time.Hour), Agent: secs(1800)}, HealthHealthy},
		{"reported interval narrows it", Cluster{LastSeenAt: ago(4 * time.Minute), Agent: secs(60)}, HealthStale},
		{"one-shot is never stale", Cluster{LastSeenAt: ago(30 * 24 * time.Hour), Agent: secs(0)}, HealthHealthy},
		{"rejection after last accept", Cluster{LastSeenAt: ago(time.Hour), LastPushErrorAt: ago(time.Minute), LastPushError: "x"}, HealthErroring},
		{"paused outranks erroring", Cluster{PausedAt: ago(time.Hour), LastPushErrorAt: ago(time.Minute), LastPushError: "x"}, HealthPaused},
		{"accept after last rejection", Cluster{LastSeenAt: ago(time.Minute), LastPushErrorAt: ago(time.Hour), LastPushError: "x"}, HealthHealthy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := is.New(t)
			h := tt.cluster.Health(now)
			is.Equal(h.State, tt.want)
			if tt.want != HealthHealthy {
				is.True(h.Reason != "")
			}
		})
	}
}

func TestShortDuration(t *testing.T) {
	is := is.New(t)
	is.Equal(shortDuration(8*time.Hour+40*time.Minute+12*time.Second), "8h40m")
	is.Equal(shortDuration(5*time.Minute), "5m")
	is.Equal(shortDuration(2*time.Hour), "2h")
	is.Equal(shortDuration(30*time.Second), "30s")
}
