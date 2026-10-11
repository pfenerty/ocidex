package grypematch

import (
	"errors"
	"testing"
	"time"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/matryer/is"
)

// closeCounter wraps a provider to observe Close.
type closeCounter struct {
	vulnerability.Provider
	closed *int
}

func (c closeCounter) Close() error { *c.closed++; return nil }

func TestDBRefresh(t *testing.T) {
	is := is.New(t)
	day1 := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	day2 := day1.Add(24 * time.Hour)

	var closed int
	built := day1
	var failNext bool
	d := NewDB(DBConfig{}, nil)
	d.open = func(bool) (vulnerability.Provider, *vulnerability.ProviderStatus, error) {
		if failNext {
			return nil, nil, errors.New("listing unreachable")
		}
		return closeCounter{mock.VulnerabilityProvider(), &closed}, &vulnerability.ProviderStatus{Built: built}, nil
	}

	m, _ := d.Matcher()
	is.True(m == nil) // nothing open before the first refresh

	changed, err := d.Refresh()
	is.NoErr(err)
	is.True(changed) // first open is a change
	m1, b := d.Matcher()
	is.True(m1 != nil)
	is.Equal(b, day1)

	changed, err = d.Refresh()
	is.NoErr(err)
	is.True(!changed)   // same build: no re-match
	is.Equal(closed, 1) // the redundant handle was closed
	m, _ = d.Matcher()
	is.Equal(m, m1) // and the open matcher kept

	built = day2
	changed, err = d.Refresh()
	is.NoErr(err)
	is.True(changed)
	is.Equal(closed, 2) // the old build was closed after the swap
	_, b = d.Matcher()
	is.Equal(b, day2)

	failNext = true
	changed, err = d.Refresh()
	is.True(err != nil)
	is.True(!changed)
	_, b = d.Matcher()
	is.Equal(b, day2) // a failed update keeps the last good database
}
