package main

import (
	"context"
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
)

func TestRunDelete_DeletesExisting(t *testing.T) {
	t.Parallel()

	var deleted bool
	st := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return &store.Item{Key: "api_key"}, nil
		},
		deleteFn: func(context.Context, string, string, store.ItemType, string) error {
			deleted = true
			return nil
		},
	}

	if err := runDelete(context.Background(), st, noopLogger{}, "identity", "api_key", "dev"); err != nil {
		t.Fatalf("runDelete() error = %v", err)
	}
	if !deleted {
		t.Fatal("store.Delete was not called")
	}
}

func TestRunDelete_NotFoundIsNoop(t *testing.T) {
	t.Parallel()

	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return nil, store.ErrNotFound
	}}

	if err := runDelete(context.Background(), st, noopLogger{}, "identity", "missing", "dev"); err != nil {
		t.Fatalf("runDelete() error = %v, want nil (idempotent no-op)", err)
	}
}

func TestRunDelete_GetErrorPropagates(t *testing.T) {
	t.Parallel()

	st := fakeStore{getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
		return nil, errTest("boom")
	}}

	if err := runDelete(context.Background(), st, noopLogger{}, "identity", "api_key", "dev"); err == nil {
		t.Fatal("runDelete() error = nil, want error")
	}
}

func TestRunDelete_DeleteErrorPropagates(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return &store.Item{Key: "api_key"}, nil
		},
		deleteFn: func(context.Context, string, string, store.ItemType, string) error {
			return errTest("boom")
		},
	}

	if err := runDelete(context.Background(), st, noopLogger{}, "identity", "api_key", "dev"); err == nil {
		t.Fatal("runDelete() error = nil, want error")
	}
}

func TestNewDeleteCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newDeleteCmd(&deps{})
	if cmd.Use != "delete <tier> <key>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "delete <tier> <key>")
	}
	if cmd.Flags().Lookup("env") == nil {
		t.Error("flag --env is not registered")
	}
}
