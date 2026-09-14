package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
)

func TestRunList_MasksValues(t *testing.T) {
	t.Parallel()

	st := fakeStore{listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
		return []*store.Item{{Key: "a"}, {Key: "b"}}, nil
	}}

	var out bytes.Buffer
	if err := runList(context.Background(), st, "dev", &out); err != nil {
		t.Fatalf("runList() error = %v", err)
	}
	want := "a=***\nb=***\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestRunList_Empty(t *testing.T) {
	t.Parallel()

	st := fakeStore{listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
		return nil, nil
	}}
	var out bytes.Buffer
	if err := runList(context.Background(), st, "dev", &out); err != nil {
		t.Fatalf("runList() error = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("output = %q, want empty", out.String())
	}
}

func TestRunList_ListError(t *testing.T) {
	t.Parallel()

	st := fakeStore{listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
		return nil, errTest("boom")
	}}
	var out bytes.Buffer
	if err := runList(context.Background(), st, "dev", &out); err == nil {
		t.Fatal("runList() error = nil, want error")
	}
}

func TestNewListCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newListCmd(&deps{})
	if cmd.Use != "list <tier>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "list <tier>")
	}
	if cmd.Flags().Lookup("env") == nil {
		t.Error("flag --env is not registered")
	}
}
