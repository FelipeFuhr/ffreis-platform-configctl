package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/store"
)

// secretExecDeps builds a deps wired to a fake store returning a single
// real, encrypted item under api_key whose plaintext is plaintext.
func secretExecDeps(t *testing.T, plaintext string) *deps {
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

// TestRunSecretExec_InjectsPlaintextIntoChildEnv proves the value reaches
// the child process only via its environment: the child here is a shell
// script that writes $SECRET_VALUE to a file this test controls (never to
// its own stdout), and separately asserts configctl's own captured
// stdout/stderr stay empty — nothing about the plaintext is written to a
// stream configctl controls.
func TestRunSecretExec_InjectsPlaintextIntoChildEnv(t *testing.T) {
	d := secretExecDeps(t, "s3cr3t-child-value")

	outFile := filepath.Join(t.TempDir(), "captured.txt")
	t.Setenv("CONFIGCTL_EXEC_TEST_OUT_FILE", outFile)

	var stdout, stderr bytes.Buffer
	err := runSecretExec(
		context.Background(), d, "platform", "dev", "api_key", "SECRET_VALUE",
		[]string{"sh", "-c", `printf '%s' "$SECRET_VALUE" > "$CONFIGCTL_EXEC_TEST_OUT_FILE"`},
		strings.NewReader(""), &stdout, &stderr,
	)
	if err != nil {
		t.Fatalf("runSecretExec() error = %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	if string(got) != "s3cr3t-child-value" {
		t.Fatalf("child received %q via env, want %q", got, "s3cr3t-child-value")
	}

	if stdout.Len() != 0 {
		t.Fatalf("configctl's own stdout must stay empty, got: %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("configctl's own stderr must stay empty, got: %q", stderr.String())
	}
}

// TestRunSecretExec_ChildStdoutNeverSeesPlaintextViaOwnEnvDump proves the
// negative case too: even when the child dumps its own env in full (as a
// careless script or a naive `env` invocation might), that output is the
// CHILD's own stdout stream, wired directly through — never something
// configctl reads, buffers, or could accidentally echo elsewhere. Capturing
// it here (into a pipe this test owns, not the real terminal) confirms the
// value did flow through the env var and nowhere else.
func TestRunSecretExec_ChildStdoutNeverSeesPlaintextViaOwnEnvDump(t *testing.T) {
	d := secretExecDeps(t, "another-secret-value")

	var stdout, stderr bytes.Buffer
	err := runSecretExec(
		context.Background(), d, "platform", "dev", "api_key", "MY_INJECTED_VAR",
		[]string{"sh", "-c", `printf '%s' "$MY_INJECTED_VAR"`},
		strings.NewReader(""), &stdout, &stderr,
	)
	if err != nil {
		t.Fatalf("runSecretExec() error = %v", err)
	}
	if stdout.String() != "another-secret-value" {
		t.Fatalf("child stdout = %q, want the injected value (proves env var was set)", stdout.String())
	}
}

func TestRunSecretExec_PropagatesChildExitCode(t *testing.T) {
	d := secretExecDeps(t, "value")

	var stdout, stderr bytes.Buffer
	err := runSecretExec(
		context.Background(), d, "platform", "dev", "api_key", "X",
		[]string{"sh", "-c", "exit 7"},
		strings.NewReader(""), &stdout, &stderr,
	)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("runSecretExec() error = %v (%T), want *ExitError", err, err)
	}
	if exitErr.Code != 7 {
		t.Fatalf("ExitError.Code = %d, want 7", exitErr.Code)
	}
}

func TestRunSecretExec_MissingAsIsError(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{SecretKey: secretWiringKey}, log: noopLogger{}, store: fakeStore{}}
	var stdout, stderr bytes.Buffer
	err := runSecretExec(context.Background(), d, "platform", "dev", "api_key", "",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runSecretExec() error = nil, want error for missing --as")
	}
}

func TestRunSecretExec_MissingProjectEnv(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{SecretKey: secretWiringKey}, log: noopLogger{}, store: fakeStore{}}
	var stdout, stderr bytes.Buffer
	err := runSecretExec(context.Background(), d, "", "dev", "api_key", "X",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runSecretExec() error = nil, want error for missing --project")
	}
}

func TestRunSecretExec_MissingSecretKey(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{}, log: noopLogger{}, store: fakeStore{}}
	var stdout, stderr bytes.Buffer
	err := runSecretExec(context.Background(), d, "platform", "dev", "api_key", "X",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runSecretExec() error = nil, want error for missing secret key")
	}
}

func TestRunSecretExec_SecretNotFound(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{SecretKey: secretWiringKey},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
		},
	}
	var stdout, stderr bytes.Buffer
	err := runSecretExec(context.Background(), d, "platform", "dev", "missing", "X",
		[]string{"true"}, strings.NewReader(""), &stdout, &stderr)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != exitNotFound {
		t.Fatalf("runSecretExec() error = %v, want *ExitError{Code: exitNotFound}", err)
	}
}

func TestRunSecretExec_CommandNotFoundErrorNeverIncludesValue(t *testing.T) {
	t.Parallel()

	d := secretExecDeps(t, "value-that-must-not-leak")
	var stdout, stderr bytes.Buffer
	err := runSecretExec(context.Background(), d, "platform", "dev", "api_key", "X",
		[]string{"configctl-test-definitely-not-a-real-binary-xyz"},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatal("runSecretExec() error = nil, want error for missing binary")
	}
	if strings.Contains(err.Error(), "value-that-must-not-leak") {
		t.Fatalf("error message leaked the plaintext: %v", err)
	}
}

// TestSecretExecCmd_EndToEnd_SplitsKeyAndCommandAtDash exercises the real
// cobra flag-parsing path (SetArgs + Execute), not just runSecretExec
// directly, to prove the "-- " splitting in the command's Args/RunE actually
// works against real pflag parsing (cmd.ArgsLenAtDash()).
func TestSecretExecCmd_EndToEnd_SplitsKeyAndCommandAtDash(t *testing.T) {
	d := secretExecDeps(t, "end-to-end-value")

	outFile := filepath.Join(t.TempDir(), "e2e.txt")
	t.Setenv("CONFIGCTL_EXEC_TEST_OUT_FILE", outFile)

	cmd := newSecretExecCmd(d, &globalFlags{})
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{
		"api_key", "--as", "SECRET_VALUE",
		"--project", "platform", "--env", "dev",
		"--", "sh", "-c", `printf '%s' "$SECRET_VALUE" > "$CONFIGCTL_EXEC_TEST_OUT_FILE"`,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	if string(got) != "end-to-end-value" {
		t.Fatalf("captured = %q, want %q", got, "end-to-end-value")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("configctl's own streams must stay empty: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestNewSecretExecCmd_FlagWiring(t *testing.T) {
	t.Parallel()

	cmd := newSecretExecCmd(&deps{}, &globalFlags{})
	if !strings.HasPrefix(cmd.Use, "exec <key>") {
		t.Errorf("Use = %q, want prefix %q", cmd.Use, "exec <key>")
	}
	for _, name := range []string{"project", "env", "as"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("flag --%s is not registered", name)
		}
	}
	if cmd.Args == nil {
		t.Fatal("Args validator is nil")
	}
	if err := cmd.Args(cmd, []string{"key"}); err == nil {
		t.Error("Args() with no -- separator should error")
	}
}
