package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/store"
)

const secretWiringKey = "01234567890123456789012345678901"

func TestNewSecretCmd_HasSubcommands(t *testing.T) {
	t.Parallel()

	cmd := newSecretCmd(&deps{}, &globalFlags{})
	if cmd.Use != "secret" {
		t.Fatalf("Use = %q, want secret", cmd.Use)
	}
	want := map[string]bool{"get": false, "set": false, "list": false, "delete": false, "rotate": false}
	for _, c := range cmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func TestSecretGetCmd_MaskedByDefault(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "api_key", Value: "ciphertext", KeyID: "kid", Version: 1}, nil
			},
		},
	}

	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("value:      ***")) {
		t.Fatalf("output should mask value, got: %s", out.String())
	}
}

func TestSecretGetCmd_RevealDecrypts(t *testing.T) {
	t.Parallel()

	enc, err := crypto.NewAESGCMEncryptor(secretWiringKey, "platform", "dev", "api_key")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	ciphertext, keyID, err := enc.Encrypt([]byte("sk_live_abc"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "api_key", Value: string(ciphertext), KeyID: keyID, Version: 1}, nil
			},
		},
	}

	cmd := newSecretGetCmd(d, &globalFlags{output: formatJSON})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")
	_ = cmd.Flags().Set("reveal", "true")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["value"] != "sk_live_abc" {
		t.Fatalf("value = %v, want sk_live_abc", got["value"])
	}
}

func TestSecretGetCmd_RevealDecryptError(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "api_key", Value: "not-valid-base64-ciphertext!!", KeyID: "", Version: 1}, nil
			},
		},
	}

	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")
	_ = cmd.Flags().Set("reveal", "true")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want decrypt error")
	}
}

func TestSecretGetCmd_MissingSecretKey(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg:   &appconfig.Config{},
		log:   noopLogger{},
		store: fakeStore{},
	}

	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error for missing secret key")
	}
}

func TestSecretGetCmd_GenericStoreError(t *testing.T) {
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

	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}

func TestSecretListCmd_Text(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return []*store.Item{{Key: "a"}, {Key: "b"}}, nil
			},
		},
	}

	cmd := newSecretListCmd(d, &globalFlags{output: "text"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	want := "a=***\nb=***\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestSecretListCmd_JSON(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return []*store.Item{{Key: "a", KeyID: "kid", Version: 2}}, nil
			},
		},
	}

	cmd := newSecretListCmd(d, &globalFlags{output: formatJSON})
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
	if len(got) != 1 || got[0]["value"] != "***" {
		t.Fatalf("got = %#v, want masked value", got)
	}
}

func TestSecretListCmd_Table(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return []*store.Item{{Key: "a", KeyID: "kid"}}, nil
			},
		},
	}

	cmd := newSecretListCmd(d, &globalFlags{output: "table"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("KEY_ID")) {
		t.Fatalf("table output missing KEY_ID header: %q", out.String())
	}
}

func TestSecretListCmd_ListError(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			listFn: func(context.Context, string, string, store.ItemType) ([]*store.Item, error) {
				return nil, errors.New("boom")
			},
		},
	}

	cmd := newSecretListCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}

func TestSecretDeleteCmd_DeletesExisting(t *testing.T) {
	t.Parallel()

	var deleted bool
	base := fakeStore{
		getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
			return &store.Item{Key: "api_key"}, nil
		},
	}
	d := &deps{log: noopLogger{}, store: deletingStore{fakeStore: base, onDelete: func() { deleted = true }}}

	cmd := newSecretDeleteCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !deleted {
		t.Fatal("store.Delete was not called")
	}
}

func TestSecretDeleteCmd_NotFoundIsNoop(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
		},
	}

	cmd := newSecretDeleteCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"missing"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, want nil (idempotent no-op)", err)
	}
}

func TestSecretDeleteCmd_GetErrorPropagates(t *testing.T) {
	t.Parallel()

	d := &deps{
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, errors.New("boom")
			},
		},
	}

	cmd := newSecretDeleteCmd(d, &globalFlags{})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"api_key"})
	_ = cmd.Flags().Set("project", "platform")
	_ = cmd.Flags().Set("env", "dev")

	if err := cmd.Execute(); err == nil {
		t.Fatal("Execute() error = nil, want error")
	}
}
