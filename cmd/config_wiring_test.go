package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/store"
)

func TestNewConfigCmd_HasSubcommands(t *testing.T) {
	t.Parallel()

	cmd := newConfigCmd(&deps{}, &globalFlags{})
	if cmd.Use != "config" {
		t.Fatalf("Use = %q, want config", cmd.Use)
	}
	want := map[string]bool{"get": false, "set": false, "list": false, "delete": false}
	for _, c := range cmd.Commands() {
		name := c.Name()
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func TestConfigGetCmd_TextSuccess(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "host", Value: "localhost"}, nil
			},
		},
	}

	cmd := newConfigGetCmd(d, &globalFlags{output: "text"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if out.String() != "localhost\n" {
		t.Fatalf("output = %q, want %q", out.String(), "localhost\n")
	}
}

func TestConfigGetCmd_JSONSuccess(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "host", Value: "localhost"}, nil
			},
		},
	}

	cmd := newConfigGetCmd(d, &globalFlags{output: formatJSON})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["value"] != "localhost" {
		t.Fatalf("value = %q, want localhost", got["value"])
	}
}

func TestConfigGetCmd_GenericStoreError(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, errors.New("ddb unavailable")
			},
		},
	}

	cmd := newConfigGetCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}

func TestConfigSetCmd_CreatesNewItem(t *testing.T) {
	t.Parallel()

	var setCalled bool
	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
			setFn: func(ctx context.Context, item *store.Item) error {
				setCalled = true
				if item.Value != "localhost" || item.Version != 0 {
					t.Errorf("item = %#v, unexpected", item)
				}
				return nil
			},
		},
	}

	cmd := newConfigSetCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host", "localhost"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !setCalled {
		t.Fatal("store.Set was not called")
	}
}

func TestConfigSetCmd_IdempotentSkipsWrite(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Value: "localhost", Version: 2, CreatedAt: time.Now()}, nil
			},
			setFn: func(context.Context, *store.Item) error {
				t.Fatal("store.Set called for an unchanged value; should be skipped")
				return nil
			},
		},
	}

	cmd := newConfigSetCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host", "localhost"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestConfigSetCmd_UpdatesExistingItem(t *testing.T) {
	t.Parallel()

	var gotVersion int64
	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Value: "old-value", Version: 2, CreatedAt: time.Now()}, nil
			},
			setFn: func(ctx context.Context, item *store.Item) error {
				gotVersion = item.Version
				return nil
			},
		},
	}

	cmd := newConfigSetCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host", "new-value"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if gotVersion != 2 {
		t.Fatalf("Set() called with Version = %d, want 2 (carried from existing)", gotVersion)
	}
}

func TestConfigSetCmd_GetErrorPropagates(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, errors.New("ddb unavailable")
			},
		},
	}

	cmd := newConfigSetCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host", "v"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}

func TestConfigSetCmd_SetErrorPropagates(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
			setFn: func(context.Context, *store.Item) error {
				return errors.New("write denied")
			},
		},
	}

	cmd := newConfigSetCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host", "v"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}

func TestConfigListCmd_Text(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return []*store.Item{{Key: "a", Value: "1"}, {Key: "b", Value: "2"}}, nil
			},
		},
	}

	cmd := newConfigListCmd(d, &globalFlags{output: "text"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	want := "a=1\nb=2\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestConfigListCmd_JSON(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return []*store.Item{{Key: "a", Value: "1", Version: 3}}, nil
			},
		},
	}

	cmd := newConfigListCmd(d, &globalFlags{output: formatJSON})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var got []map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 || got[0]["key"] != "a" {
		t.Fatalf("got = %#v, unexpected", got)
	}
}

func TestConfigListCmd_Table(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return []*store.Item{{Key: "a", Value: "1", Version: 1, UpdatedAt: time.Now()}}, nil
			},
		},
	}

	cmd := newConfigListCmd(d, &globalFlags{output: "table"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("KEY")) || !bytes.Contains(out.Bytes(), []byte("a")) {
		t.Fatalf("table output missing expected content: %q", out.String())
	}
}

func TestConfigListCmd_ListError(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return nil, errors.New("boom")
			},
		},
	}

	cmd := newConfigListCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}

func TestConfigDeleteCmd_DeletesExisting(t *testing.T) {
	t.Parallel()

	var deleted bool
	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "host"}, nil
			},
		},
	}
	// Delete isn't part of fakeStore's configurable functions; wrap it.
	d.store = deletingStore{fakeStore: d.store.(fakeStore), onDelete: func() { deleted = true }}

	cmd := newConfigDeleteCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !deleted {
		t.Fatal("store.Delete was not called")
	}
}

func TestConfigDeleteCmd_NotFoundIsNoop(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
		},
	}

	cmd := newConfigDeleteCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"missing"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, want nil (idempotent no-op)", err)
	}
}

func TestConfigDeleteCmd_GetErrorPropagates(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, errors.New("boom")
			},
		},
	}

	cmd := newConfigDeleteCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"host"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}

// deletingStore wraps a fakeStore to add a working Delete, since fakeStore's
// Delete always panics (unimplemented) and several tests need a real one.
type deletingStore struct {
	fakeStore
	onDelete func()
}

func (d deletingStore) Delete(context.Context, string, string, store.ItemType, string) error {
	if d.onDelete != nil {
		d.onDelete()
	}
	return nil
}
