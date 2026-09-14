package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func newSecretExportEnvCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env, as, out string

	cmd := &cobra.Command{
		Use:   "export-env <key> --as NAME --out <path>",
		Short: "Write a shell-sourceable export of a decrypted secret to a file",
		Long: `export-env decrypts <key> and writes a single line, export NAME=<value>
(shell-quoted), to the file named by the required --out flag.

There is no default output location: writing to stdout or an implicit path
would risk exactly the transcript leak this vault is meant to prevent, so
the caller must say exactly where the value goes. --as (the env var name)
is required for the same reason --as is required on 'secret exec' — no
silent default such as uppercasing the key, since that could collide or
surprise.

The file is written with mode 0600. configctl itself prints nothing but a
confirmation of the path it wrote — never the value — to stdout.

The caller is responsible for shredding the file once it is no longer
needed (e.g. 'shred -u <path>' or 'rm -P <path>') — configctl does not do
this for you, since it has no way to know when the caller is done with it.

Example:
  platform-configctl secret export-env stripe_key --as STRIPE_KEY \
    --project payments --env prod --out /tmp/stripe_key.env
  source /tmp/stripe_key.env && shred -u /tmp/stripe_key.env`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretExportEnv(cmd.Context(), d, project, env, args[0], as, out, os.WriteFile, cmd.OutOrStdout())
		},
	}

	addProjectEnvFlags(cmd, d, &project, &env)
	cmd.Flags().StringVar(&as, flagAs, "", "Environment variable name to export the decrypted value as (required)")
	cmd.Flags().StringVar(&out, flagOut, "", "File path to write the export line to, mode 0600 (required, no default)")
	_ = cmd.MarkFlagRequired(flagAs)
	_ = cmd.MarkFlagRequired(flagOut)
	_ = gf
	return cmd
}

func runSecretExportEnv(
	ctx context.Context,
	d *deps,
	project, env, key, as, out string,
	writeFile func(string, []byte, os.FileMode) error,
	stdout io.Writer,
) error {
	if err := requireProjectEnv(project, env); err != nil {
		return err
	}
	if as == "" {
		return errors.New("--as is required: the environment variable name to export the decrypted value as")
	}
	if out == "" {
		return errors.New("--out is required: export-env never defaults to stdout or an implicit location")
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

	line := "export " + as + "=" + shellQuoteSingle(string(plaintext)) + "\n"
	if err := writeFile(out, []byte(line), 0o600); err != nil {
		return fmt.Errorf("write export file: %w", err)
	}

	// Never log or print the value — only the key name, target env var name,
	// and destination path.
	d.log.Info("secret exported to file",
		zap.String("key", key),
		zap.String(flagAs, as),
		zap.String("path", out),
	)

	_, err = fmt.Fprintf(stdout, "wrote %s (mode 0600) — remember to shred it once you're done, e.g.: shred -u %s\n", out, out)
	return err
}

// shellQuoteSingle wraps s in single quotes for safe use in a POSIX shell
// 'export NAME=...' line, escaping any embedded single quote.
func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
