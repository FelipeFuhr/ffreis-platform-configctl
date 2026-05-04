package cmd

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/store"
)

func TestExecuteCommand_ReturnsExitCodeAndErrorText(t *testing.T) {
	t.Parallel()

	command := &cobra.Command{
		RunE: func(*cobra.Command, []string) error {
			return &ExitError{Code: 7, Err: errors.New("boom")}
		},
	}

	var stderr bytes.Buffer
	code := executeCommand(command, &stderr)
	if code != 7 {
		t.Fatalf("executeCommand() code = %d, want 7", code)
	}
	if got := stderr.String(); got != "error: boom\n" {
		t.Fatalf("executeCommand() stderr = %q", got)
	}
}

func TestConfigGet_NotFoundReturnsExitError(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
		},
	}

	cmd := newConfigGetCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"missing"})
	cmd.Flags().Set("project", "platform")
	cmd.Flags().Set("env", "dev")

	err := cmd.Execute()
	exitErr, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T (%v)", err, err)
	}
	if exitErr.Code != exitNotFound {
		t.Fatalf("ExitError.Code = %d, want %d", exitErr.Code, exitNotFound)
	}
}

func TestSecretGet_NotFoundReturnsExitError(t *testing.T) {
	t.Parallel()

	d := &deps{
		cfg: &appconfig.Config{SecretKey: "01234567890123456789012345678901"},
		log: noopLogger{},
		store: fakeStore{
			getFn: func(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
				return nil, store.ErrNotFound
			},
		},
	}

	cmd := newSecretGetCmd(d, &globalFlags{output: "text"})
	cmd.SetContext(context.Background())
	cmd.SetArgs([]string{"missing"})
	cmd.Flags().Set("project", "platform")
	cmd.Flags().Set("env", "dev")

	err := cmd.Execute()
	exitErr, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T (%v)", err, err)
	}
	if exitErr.Code != exitNotFound {
		t.Fatalf("ExitError.Code = %d, want %d", exitErr.Code, exitNotFound)
	}
}

func TestExitCodeForError_Default(t *testing.T) {
	t.Parallel()

	if got := exitCodeForError(errors.New("boom")); got != exitError {
		t.Fatalf("exitCodeForError() = %d, want %d", got, exitError)
	}
}
