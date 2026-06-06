package client

import (
	"context"
	"errors"
	"testing"

	"github.com/matryer/is"
)

func TestFakeClient_NilFieldReturnsZeroValue(t *testing.T) {
	is := is.New(t)
	f := &FakeClient{}

	// Unset fields return zero values and nil error.
	reg, err := f.GetRegistry(context.Background(), "reg-1")
	is.NoErr(err)
	is.Equal(reg, RegistryResponse{})

	page, err := f.ListRegistries(context.Background(), PageOpts{})
	is.NoErr(err)
	is.Equal(len(page.Data), 0)

	err = f.DeleteRegistry(context.Background(), "reg-1")
	is.NoErr(err)
}

func TestFakeClient_SetFieldIsCalled(t *testing.T) {
	is := is.New(t)
	sentinel := errors.New("injected error")

	f := &FakeClient{
		GetRegistryFn: func(ctx context.Context, id string) (RegistryResponse, error) {
			return RegistryResponse{Id: id, Name: "stubbed"}, nil
		},
		DeleteRegistryFn: func(ctx context.Context, id string) error {
			return sentinel
		},
	}

	reg, err := f.GetRegistry(context.Background(), "reg-42")
	is.NoErr(err)
	is.Equal(reg.Id, "reg-42")
	is.Equal(reg.Name, "stubbed")

	err = f.DeleteRegistry(context.Background(), "reg-42")
	is.True(errors.Is(err, sentinel))
}
