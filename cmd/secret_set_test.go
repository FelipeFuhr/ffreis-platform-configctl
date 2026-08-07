package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/store"
)

// TestNewSecretSetCmdFlagWiring pins the command surface without touching
// os.Stdin — runSecretSet takes an injected io.Reader and is exercised
// directly by the tests below, so this only needs to prove the constructor
// wires the right flags. See secret_rotate_wiring_test.go for the precedent.
func TestNewSecretSetCmdFlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newSecretSetCmd(&deps{}, &globalFlags{})
	if cmd.Use != "set <key>" {
		t.Errorf("Use = %q, want %q", cmd.Use, "set <key>")
	}
	for _, name := range []string{"project", "env"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	if cmd.Args == nil {
		t.Error("Args is nil; set takes exactly one positional argument")
	}
	if !strings.Contains(cmd.Long, "stdin") {
		t.Error("long help does not mention stdin — the only supported input source")
	}
}

func TestRunSecretSet_CreatesNewItem(t *testing.T) {
	t.Parallel()

	var setItem *store.Item
	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
			setFn: func(ctx context.Context, item *store.Item) error {
				setItem = item
				return nil
			},
		},
	}

	if err := runSecretSet(context.Background(), d, "platform", "dev", "api_key", strings.NewReader("sk_live_abc")); err != nil {
		t.Fatalf("runSecretSet() error = %v", err)
	}
	if setItem == nil {
		t.Fatal("store.Set was not called")
	}
	if setItem.Version != 0 {
		t.Fatalf("Version = %d, want 0 for a new item", setItem.Version)
	}
	if !setItem.Encrypted {
		t.Fatal("Encrypted = false, want true")
	}
	if setItem.Value == "sk_live_abc" {
		t.Fatal("stored value must be ciphertext, not plaintext")
	}
}

func TestRunSecretSet_CarriesExistingVersion(t *testing.T) {
	t.Parallel()

	createdAt := time.Now().Add(-time.Hour)
	var setItem *store.Item
	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Version: 4, CreatedAt: createdAt}, nil
			},
			setFn: func(ctx context.Context, item *store.Item) error {
				setItem = item
				return nil
			},
		},
	}

	if err := runSecretSet(context.Background(), d, "platform", "dev", "api_key", strings.NewReader("new-value")); err != nil {
		t.Fatalf("runSecretSet() error = %v", err)
	}
	if setItem.Version != 4 {
		t.Fatalf("Version = %d, want 4 (carried from existing)", setItem.Version)
	}
	if !setItem.CreatedAt.Equal(createdAt) {
		t.Fatalf("CreatedAt = %v, want %v (carried from existing)", setItem.CreatedAt, createdAt)
	}
}

func TestRunSecretSet_MissingProjectEnv(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{SecretKey: secretWiringKey}, log: noopLogger{}, store: fakeStore{}}
	if err := runSecretSet(context.Background(), d, "", "dev", "k", strings.NewReader("v")); err == nil {
		t.Fatal("runSecretSet() error = nil, want error")
	}
}

func TestRunSecretSet_MissingSecretKey(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{}, log: noopLogger{}, store: fakeStore{}}
	if err := runSecretSet(context.Background(), d, "platform", "dev", "k", strings.NewReader("v")); err == nil {
		t.Fatal("runSecretSet() error = nil, want error")
	}
}

func TestRunSecretSet_EmptyStdinIsError(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{SecretKey: secretWiringKey}, log: noopLogger{}, store: fakeStore{}}
	if err := runSecretSet(context.Background(), d, "platform", "dev", "k", strings.NewReader("")); err == nil {
		t.Fatal("runSecretSet() error = nil, want error for empty stdin")
	}
}

// errReader always fails, simulating a broken stdin pipe.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("pipe closed") }

func TestRunSecretSet_StdinReadError(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{SecretKey: secretWiringKey}, log: noopLogger{}, store: fakeStore{}}
	if err := runSecretSet(context.Background(), d, "platform", "dev", "k", errReader{}); err == nil {
		t.Fatal("runSecretSet() error = nil, want error")
	}
}

func TestRunSecretSet_ExistingVersionLookupError(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, errors.New("ddb unavailable")
			},
		},
	}
	if err := runSecretSet(context.Background(), d, "platform", "dev", "k", strings.NewReader("v")); err == nil {
		t.Fatal("runSecretSet() error = nil, want error")
	}
}

func TestRunSecretSet_StoreSetError(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
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
	if err := runSecretSet(context.Background(), d, "platform", "dev", "k", strings.NewReader("v")); err == nil {
		t.Fatal("runSecretSet() error = nil, want error")
	}
}

func TestReadStdin_TrimsTrailingNewlines(t *testing.T) {
	t.Parallel()

	got, err := readStdin(strings.NewReader("secret-value\n"))
	if err != nil {
		t.Fatalf("readStdin() error = %v", err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("readStdin() = %q, want %q", got, "secret-value")
	}
}

func TestReadStdin_TrimsCRLF(t *testing.T) {
	t.Parallel()

	got, err := readStdin(strings.NewReader("secret-value\r\n"))
	if err != nil {
		t.Fatalf("readStdin() error = %v", err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("readStdin() = %q, want %q", got, "secret-value")
	}
}

func TestReadSecretValueFromStdin_EmptyIsError(t *testing.T) {
	t.Parallel()

	if _, err := readSecretValueFromStdin(strings.NewReader("\n")); err == nil {
		t.Fatal("readSecretValueFromStdin() error = nil, want error for effectively-empty input")
	}
}

func TestEncryptSecretValue_MissingKeyErrors(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{}}
	if _, _, err := encryptSecretValue(d, "platform", "dev", "k", []byte("v")); err == nil {
		t.Fatal("encryptSecretValue() error = nil, want error when SecretKey is empty")
	}
}

func TestExistingSecretVersion_NotFoundReturnsZero(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return nil, store.ErrNotFound
		},
	}
	version, createdAt, err := existingSecretVersion(context.Background(), st, "platform", "dev", "k")
	if err != nil {
		t.Fatalf("existingSecretVersion() error = %v", err)
	}
	if version != 0 || !createdAt.IsZero() {
		t.Fatalf("version=%d createdAt=%v, want 0/zero", version, createdAt)
	}
}

func TestExistingSecretVersion_PropagatesError(t *testing.T) {
	t.Parallel()

	st := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return nil, errors.New("boom")
		},
	}
	if _, _, err := existingSecretVersion(context.Background(), st, "platform", "dev", "k"); err == nil {
		t.Fatal("existingSecretVersion() error = nil, want error")
	}
}

func TestBuildSecretItem_Fields(t *testing.T) {
	t.Parallel()

	created := time.Now().Add(-time.Hour)
	item := buildSecretItem("platform", "dev", "k", []byte("ciphertext"), "kid", 2, created, "tester")
	if item.Project != "platform" || item.Env != "dev" || item.Key != "k" {
		t.Fatalf("item location = %#v, unexpected", item)
	}
	if !item.Encrypted || item.KeyID != "kid" || item.Version != 2 {
		t.Fatalf("item = %#v, unexpected", item)
	}
	if item.UpdatedBy != "tester" {
		t.Fatalf("UpdatedBy = %q, want tester", item.UpdatedBy)
	}
	if item.Checksum == "" {
		t.Fatal("Checksum is empty")
	}
	if !item.CreatedAt.Equal(created) {
		t.Fatalf("CreatedAt = %v, want %v", item.CreatedAt, created)
	}
}
