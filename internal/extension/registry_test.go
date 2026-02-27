package extension

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	matryer "github.com/matryer/is"

	"github.com/pfenerty/ocidex/internal/event"
)

// fakeExtension records lifecycle calls for testing.
type fakeExtension struct {
	name     string
	initErr  error
	startErr error
	stopErr  error

	initCalled  bool
	startCalled bool
	stopCalled  bool
	order       *[]string // shared slice to track call order
}

func (f *fakeExtension) Name() string { return f.name }

func (f *fakeExtension) Init(_ *event.Bus) error {
	f.initCalled = true
	if f.order != nil {
		*f.order = append(*f.order, f.name+".init")
	}
	return f.initErr
}

func (f *fakeExtension) Start(_ context.Context) error {
	f.startCalled = true
	if f.order != nil {
		*f.order = append(*f.order, f.name+".start")
	}
	return f.startErr
}

func (f *fakeExtension) Stop() error {
	f.stopCalled = true
	if f.order != nil {
		*f.order = append(*f.order, f.name+".stop")
	}
	return f.stopErr
}

func TestRegistry_Lifecycle(t *testing.T) {
	is := matryer.New(t)
	bus := event.NewBus(slog.Default())
	reg := NewRegistry(bus, slog.Default())

	var order []string
	a := &fakeExtension{name: "a", order: &order}
	b := &fakeExtension{name: "b", order: &order}

	reg.Register(a)
	reg.Register(b)

	is.NoErr(reg.InitAll())
	is.True(a.initCalled)
	is.True(b.initCalled)

	is.NoErr(reg.StartAll(t.Context()))
	is.True(a.startCalled)
	is.True(b.startCalled)

	is.NoErr(reg.StopAll())
	is.True(a.stopCalled)
	is.True(b.stopCalled)

	// Init and Start in registration order, Stop in reverse.
	is.Equal(order, []string{
		"a.init", "b.init",
		"a.start", "b.start",
		"b.stop", "a.stop",
	})
}

func TestRegistry_InitFailFast(t *testing.T) {
	is := matryer.New(t)
	bus := event.NewBus(slog.Default())
	reg := NewRegistry(bus, slog.Default())

	a := &fakeExtension{name: "a", initErr: errors.New("broken")}
	b := &fakeExtension{name: "b"}

	reg.Register(a)
	reg.Register(b)

	err := reg.InitAll()
	is.True(err != nil)
	is.True(!b.initCalled) // b should not have been initialized
}

func TestRegistry_StopContinuesOnError(t *testing.T) {
	is := matryer.New(t)
	bus := event.NewBus(slog.Default())
	reg := NewRegistry(bus, slog.Default())

	a := &fakeExtension{name: "a"}
	b := &fakeExtension{name: "b", stopErr: errors.New("cleanup failed")}

	reg.Register(a)
	reg.Register(b)

	is.NoErr(reg.InitAll())
	err := reg.StopAll()
	is.True(err != nil)
	is.True(a.stopCalled) // a should still be stopped despite b's error
}
