package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/store"
)

// sourceAndPrintVar sources path in a real POSIX shell subprocess and prints
// the named variable — used to prove shellQuoteSingle's output is not just
// textually plausible but actually parses correctly.
func sourceAndPrintVar(path, varName string) (string, error) {
	c := exec.CommandContext(context.Background(), "sh", "-c", fmt.Sprintf(`. "$1" && printf '%%s' "$%s"`, varName), "sh", path)
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("run: %w", err)
	}
	return string(out), nil
}

func secretExportEnvDeps(t *testing.T, plaintext string) *deps {
	t.Helper()

	enc, err := crypto.NewAESGCMEncryptor(secretWiringKey, "platform", "dev", "api_key")
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	ciphertext, keyID, err := enc.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return &store.Item{Key: "api_key", Value: string(ciphertext), KeyID: keyID, Version: 1}, nil
			},
		},
	}
}

// TestRunSecretExportEnv_WritesShellQuotedFileMode0600 proves the write goes
// to the caller-chosen file (via an injected writeFile, not the real
// filesystem) with the right contents and mode, and that configctl's own
// stdout only ever gets the path confirmation — never the value.
func TestRunSecretExportEnv_WritesShellQuotedFileMode0600(t *testing.T) {
	d := secretExportEnvDeps(t, "value with 'quotes' inside")

	var writtenPath string
	var writtenData []byte
	var writtenMode os.FileMode
	writeFile := func(path string, data []byte, mode os.FileMode) error {
		writtenPath, writtenData, writtenMode = path, data, mode
		return nil
	}

	var stdout bytes.Buffer
	err := runSecretExportEnv(context.Background(), d, "platform", "dev", "api_key", "SECRET_VALUE", "/tmp/out.env", writeFile, &stdout)
	if err != nil {
		t.Fatalf("runSecretExportEnv() error = %v", err)
	}

	if writtenPath != "/tmp/out.env" {
		t.Fatalf("writeFile path = %q, want /tmp/out.env", writtenPath)
	}
	if writtenMode != 0o600 {
		t.Fatalf("writeFile mode = %o, want 0600", writtenMode)
	}
	wantLine := `export SECRET_VALUE='value with '\''quotes'\'' inside'` + "\n"
	if string(writtenData) != wantLine {
		t.Fatalf("writeFile data = %q, want %q", writtenData, wantLine)
	}

	if bytes.Contains(stdout.Bytes(), []byte("value with")) {
		t.Fatalf("plaintext leaked to configctl's own stdout: %q", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("/tmp/out.env")) {
		t.Fatalf("stdout should confirm the path it wrote, got: %q", stdout.String())
	}
}

// TestRunSecretExportEnv_ShellQuotedValueSourcesCleanly proves the quoting is
// not just textually plausible but actually round-trips through a real
// POSIX shell — write the line, source it, and read the variable back.
func TestRunSecretExportEnv_ShellQuotedValueSourcesCleanly(t *testing.T) {
	const value = `tricky$val'ue "with" $(command) substitution`
	d := secretExportEnvDeps(t, value)

	dir := t.TempDir()
	path := dir + "/out.env"

	var stdout bytes.Buffer
	err := runSecretExportEnv(context.Background(), d, "platform", "dev", "api_key", "ROUNDTRIP_VALUE", path, os.WriteFile, &stdout)
	if err != nil {
		t.Fatalf("runSecretExportEnv() error = %v", err)
	}

	got, err := sourceAndPrintVar(path, "ROUNDTRIP_VALUE")
	if err != nil {
		t.Fatalf("source+print failed: %v", err)
	}
	if got != value {
		t.Fatalf("round-tripped value = %q, want %q", got, value)
	}
}

func TestRunSecretExportEnv_MissingOutIsError(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{SecretKey: secretWiringKey}, log: noopLogger{}, store: fakeStore{}}
	var stdout bytes.Buffer
	err := runSecretExportEnv(context.Background(), d, "platform", "dev", "api_key", "X", "",
		func(string, []byte, os.FileMode) error { return nil }, &stdout)
	if err == nil {
		t.Fatal("runSecretExportEnv() error = nil, want error for missing --out")
	}
}

func TestRunSecretExportEnv_MissingAsIsError(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{SecretKey: secretWiringKey}, log: noopLogger{}, store: fakeStore{}}
	var stdout bytes.Buffer
	err := runSecretExportEnv(context.Background(), d, "platform", "dev", "api_key", "", "/tmp/out.env",
		func(string, []byte, os.FileMode) error { return nil }, &stdout)
	if err == nil {
		t.Fatal("runSecretExportEnv() error = nil, want error for missing --as")
	}
}

func TestRunSecretExportEnv_WriteFileErrorPropagates(t *testing.T) {
	d := secretExportEnvDeps(t, "value")
	var stdout bytes.Buffer
	err := runSecretExportEnv(context.Background(), d, "platform", "dev", "api_key", "X", "/tmp/out.env",
		func(string, []byte, os.FileMode) error { return errors.New("disk full") }, &stdout)
	if err == nil {
		t.Fatal("runSecretExportEnv() error = nil, want error propagated from writeFile")
	}
}

func TestNewSecretExportEnvCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newSecretExportEnvCmd(&deps{}, &globalFlags{})
	if !strings.HasPrefix(cmd.Use, "export-env <key>") {
		t.Errorf("Use = %q, want prefix %q", cmd.Use, "export-env <key>")
	}
	for _, name := range []string{"project", "env", "as", "out"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	if !strings.Contains(cmd.Long, "shred") {
		t.Error("long help does not document the caller's responsibility to shred the file")
	}
}

func TestShellQuoteSingle(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"simple":       `'simple'`,
		"":             `''`,
		"it's":         `'it'\''s'`,
		"a'b'c":        `'a'\''b'\''c'`,
		"$(rm -rf /)":  `'$(rm -rf /)'`,
		"back\\slash":  `'back\slash'`,
		"new\nline":    "'new\nline'",
		"double\"quot": `'double"quot'`,
	}
	for in, want := range cases {
		if got := shellQuoteSingle(in); got != want {
			t.Errorf("shellQuoteSingle(%q) = %q, want %q", in, got, want)
		}
	}
}
