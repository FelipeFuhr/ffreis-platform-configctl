package cmd

import (
	"bytes"
	"sort"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestSecretSetCmd_HasNoPlaintextValueFlag is the regression test the
// mandate specifically calls for: a test that would catch a regression
// where a secret value became readable via --flag rather than stdin.
// TestNewSecretSetCmdFlagWiring (secret_set_test.go) checks that --project
// and --env ARE registered and that the help text mentions stdin, but never
// asserts anything is ABSENT — it would not notice a future PR silently
// adding e.g. `--value` (or --secret, --password, --plaintext) alongside
// stdin. This asserts, by name, that none of the plausible plaintext-input
// flag names exist on `secret set` AND — the stronger, drift-proof form —
// that the command's entire flag set is exactly {project, env}: any future
// flag of ANY name fails this test until a human deliberately updates it,
// forcing that addition to be noticed and justified rather than sliding in
// unreviewed.
func TestSecretSetCmd_HasNoPlaintextValueFlag(t *testing.T) {
	t.Parallel()

	cmd := newSecretSetCmd(&deps{}, &globalFlags{})

	for _, leaky := range []string{"value", "secret", "password", "plaintext", "pass", "content"} {
		if f := cmd.Flags().Lookup(leaky); f != nil {
			t.Errorf("secret set has a --%s flag (%+v) — secret plaintext must only be readable from stdin, never a flag/os.Args", leaky, f)
		}
	}

	var names []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		names = append(names, f.Name)
	})
	sort.Strings(names)

	want := []string{"env", "project"}
	if len(names) != len(want) {
		t.Fatalf("secret set flag set = %v, want exactly %v — any new flag on this command must be reviewed for secret-leak risk", names, want)
	}
	for i, n := range names {
		if n != want[i] {
			t.Fatalf("secret set flag set = %v, want exactly %v", names, want)
		}
	}
}

// TestExecuteCommand_SuccessReturnsExitOK completes the three-exit-code
// picture at the executeCommand level. TestExecuteCommand_ReturnsExitCodeAndErrorText
// (get_exit_test.go) only exercises the ExitError{Code: 7} path, and
// TestExitCodeForError_Default only exercises exitCodeForError directly for
// a generic error — neither ever proves executeCommand itself returns
// exitOK (0) and writes nothing to stderr when RunE succeeds.
func TestExecuteCommand_SuccessReturnsExitOK(t *testing.T) {
	t.Parallel()

	command := &cobra.Command{
		RunE: func(*cobra.Command, []string) error { return nil },
	}

	var stderr bytes.Buffer
	code := executeCommand(command, &stderr)
	if code != exitOK {
		t.Fatalf("executeCommand() code = %d, want exitOK (%d)", code, exitOK)
	}
	if stderr.Len() != 0 {
		t.Fatalf("executeCommand() on success wrote to stderr: %q, want nothing", stderr.String())
	}
}
