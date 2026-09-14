package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newSecretExecCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env, as string

	cmd := &cobra.Command{
		Use:   "exec <key> --as NAME -- <cmd> [args...]",
		Short: "Decrypt a secret in-process and run a child command with it injected into the environment",
		Long: `exec decrypts <key> and runs the command after "--" with the plaintext
injected into the child process's environment as NAME=<value> (NAME set via
the required --as flag — there is no default, since guessing one, e.g. by
uppercasing the key, risks a silent collision or surprise).

The plaintext is never written to configctl's own stdout or stderr, never
logged (not even at debug level), and never appears in an error message — it
exists only in this process's memory and in the child process's environment
block. Use this instead of 'secret get --reveal' piped into a shell export
whenever a command needs the secret value: nothing about the value touches a
stream that could land in a terminal transcript or an AI agent session log.

The child's own stdin/stdout/stderr are connected directly to this process's
— configctl does not buffer or inspect them — and its exit code is
propagated as this command's exit code.

Example:
  platform-configctl secret exec stripe_key --as STRIPE_KEY \
    --project payments --env prod -- ./deploy.sh`,
		Args: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash != 1 {
				return errors.New("usage: secret exec <key> --as NAME -- <cmd> [args...] (exactly one key before --)")
			}
			if len(args) <= dash {
				return errors.New("missing command after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			key := args[0]
			childArgs := args[dash:]
			return runSecretExec(cmd.Context(), d, project, env, key, as, childArgs,
				cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}

	addProjectEnvFlags(cmd, d, &project, &env)
	cmd.Flags().StringVar(&as, flagAs, "", "Environment variable name to inject the decrypted value as (required)")
	_ = cmd.MarkFlagRequired(flagAs)
	_ = gf
	return cmd
}

func runSecretExec(
	ctx context.Context,
	d *deps,
	project, env, key, as string,
	childArgs []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	if err := requireProjectEnv(project, env); err != nil {
		return err
	}
	if as == "" {
		return errors.New("--as is required: the environment variable name to inject the decrypted value as")
	}
	if err := d.cfg.RequireSecretKey(); err != nil {
		return err
	}

	item, err := getSecretItem(ctx, d, project, env, key)
	if err != nil {
		return err
	}
	plaintext, err := decryptSecretItem(d, project, env, item)
	if err != nil {
		return err
	}

	// Never log the value itself — key name and target env var name only.
	d.log.Debug("running child process with secret injected into its environment",
		zap.String("key", key),
		zap.String(flagAs, as),
	)

	return runChildWithSecretEnv(ctx, as, plaintext, childArgs, stdin, stdout, stderr)
}

// runChildWithSecretEnv runs childArgs[0] with childArgs[1:] as its
// arguments, injecting as=plaintext into its environment. The child's own
// stdin/stdout/stderr are wired directly to the given streams — configctl
// never reads, buffers, or logs anything the child writes.
func runChildWithSecretEnv(
	ctx context.Context,
	as string,
	plaintext []byte,
	childArgs []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
) error {
	// #nosec G204 -- childArgs[0] is the operator-supplied command after "--",
	// exactly as a shell would run it; this is the documented purpose of exec.
	c := exec.CommandContext(ctx, childArgs[0], childArgs[1:]...)
	c.Env = append(os.Environ(), as+"="+string(plaintext))
	c.Stdin = stdin
	c.Stdout = stdout
	c.Stderr = stderr

	err := c.Run()
	if err == nil {
		return nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return &ExitError{Code: exitErr.ExitCode()}
	}
	// Any other failure (e.g. command not found) comes from exec.Error /
	// os.PathError, whose text is only ever the command name — never env
	// values — so it is safe to wrap and surface directly.
	return fmt.Errorf("run child command %q: %w", childArgs[0], err)
}
