package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/guard"
	"github.com/ffreis/platform-configctl/internal/store"
)

func newSecretGetCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string
	var reveal bool

	cmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Get a secret (metadata + fingerprint only, unless --reveal is set)",
		Long: `get prints secret metadata and a one-way fingerprint by default.

The fingerprint is the first 8 bytes of sha256(plaintext), hex-encoded. It
lets an operator confirm "is this the secret I think it is" by comparing
digests across environments or against a known value, without the plaintext
ever being displayed — the fingerprint is computed internally (the secret key
is still required) but only the digest leaves this process.

Pass --reveal to print the actual plaintext value. --reveal is refused
outright when ` + envNoReveal + ` is set to a truthy value (1/true/yes/on) —
a fleet-wide kill switch for the case where stdout is not a safe place for a
secret to land, such as an AI agent session whose transcript is persisted.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretGet(cmd.Context(), d, gf.output, project, env, args[0], reveal, cmd.OutOrStdout())
		},
	}

	addProjectEnvFlags(cmd, d, &project, &env)
	cmd.Flags().BoolVar(&reveal, "reveal", false, "Decrypt and print the plaintext value")
	return cmd
}

func runSecretGet(
	ctx context.Context,
	d *deps,
	outputFormat string,
	project, env, key string,
	reveal bool,
	stdout io.Writer,
) error {
	if err := requireProjectEnv(project, env); err != nil {
		return err
	}
	if err := d.cfg.RequireSecretKey(); err != nil {
		return err
	}
	// Checked before any decrypt is attempted: the kill switch refuses the
	// whole reveal path outright, not just the final print.
	if reveal && isEnvTruthy(envNoReveal) {
		return fmt.Errorf(
			"--reveal refused: %s is set — this environment has disabled printing secret plaintext "+
				"(use 'secret exec' or 'secret export-env' instead, or unset %s to override)",
			envNoReveal, envNoReveal,
		)
	}

	item, err := getSecretItem(ctx, d, project, env, key)
	if err != nil {
		return err
	}

	plaintext, err := decryptSecretItem(d, project, env, item)
	if err != nil {
		return err
	}
	fingerprint := secretFingerprint(plaintext)

	displayValue := "***"
	if reveal {
		displayValue = string(plaintext)
	}

	return writeSecretGetOutput(stdout, outputFormat, item, displayValue, fingerprint)
}

func getSecretItem(ctx context.Context, d *deps, project, env, key string) (*store.Item, error) {
	item, err := d.store.Get(ctx, project, env, store.ItemTypeSecret, key)
	if err == nil {
		return item, nil
	}
	if errors.Is(err, store.ErrNotFound) {
		d.log.Warn("secret not found", zap.String("key", key))
		return nil, &ExitError{Code: exitNotFound}
	}
	return nil, fmt.Errorf("get secret: %w", err)
}

// decryptSecretItem decrypts item's ciphertext with the currently configured
// secret key. This is always called by 'secret get' — even when --reveal is
// not set — because the fingerprint (see secretFingerprint) is computed from
// the plaintext and must be available regardless of --reveal.
func decryptSecretItem(d *deps, project, env string, item *store.Item) ([]byte, error) {
	enc, err := crypto.NewAESGCMEncryptor(d.cfg.SecretKey, project, env, item.Key)
	if err != nil {
		return nil, err
	}
	plaintext, err := enc.Decrypt([]byte(item.Value), item.KeyID)
	if errors.Is(err, crypto.ErrLegacyAAD) {
		// Blob was encrypted without key-name binding. Log a migration hint and
		// return the plaintext — the next `secret set` will re-encrypt with the
		// current AAD automatically.
		d.log.Warn("legacy AAD detected: re-run 'secret set' to upgrade ciphertext",
			zap.String("key", item.Key))
		return plaintext, nil
	}
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	return plaintext, nil
}

// secretFingerprint returns a short, one-way identifier for plaintext. Thin
// wrapper over internal/guard so vaultctl's `get` reuses the exact same
// fingerprint logic rather than reimplementing it — see guard.Fingerprint
// for the full doc.
func secretFingerprint(plaintext []byte) string {
	return guard.Fingerprint(plaintext)
}

func writeSecretGetOutput(w io.Writer, outputFormat string, item *store.Item, displayValue, fingerprint string) error {
	if outputFormat == formatJSON {
		out := map[string]interface{}{
			"key":         item.Key,
			keyValue:      displayValue,
			"fingerprint": fingerprint,
			"version":     item.Version,
			"updated_at":  item.UpdatedAt,
			"updated_by":  item.UpdatedBy,
			"key_id":      item.KeyID,
		}
		return json.NewEncoder(w).Encode(out)
	}

	_, _ = fmt.Fprintf(w, "%-13s%s\n", "key:", item.Key)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "value:", displayValue)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "fingerprint:", fingerprint)
	_, _ = fmt.Fprintf(w, "%-13s%d\n", "version:", item.Version)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "updated_at:", item.UpdatedAt.Format("2006-01-02T15:04:05Z"))
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "updated_by:", item.UpdatedBy)
	_, _ = fmt.Fprintf(w, "%-13s%s\n", "key_id:", item.KeyID)
	return nil
}
