package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/crypto"
	"github.com/ffreis/platform-configctl/internal/store"
)

func newSecretGetCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string
	var reveal bool

	cmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Get a secret (metadata only unless --reveal is set)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretGet(cmd.Context(), d, gf.output, project, env, args[0], reveal, os.Stdout)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
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

	item, err := getSecretItem(ctx, d, project, env, key)
	if err != nil {
		return err
	}

	displayValue, err := secretDisplayValue(d, project, env, item, reveal)
	if err != nil {
		return err
	}

	return writeSecretGetOutput(stdout, outputFormat, item, displayValue)
}

func getSecretItem(ctx context.Context, d *deps, project, env, key string) (*store.Item, error) {
	item, err := d.store.Get(ctx, project, env, store.ItemTypeSecret, key)
	if err == nil {
		return item, nil
	}
	if errors.Is(err, store.ErrNotFound) {
		d.log.Warn("secret not found", zap.String("key", key))
		os.Exit(2)
	}
	return nil, fmt.Errorf("get secret: %w", err)
}

func secretDisplayValue(d *deps, project, env string, item *store.Item, reveal bool) (string, error) {
	if !reveal {
		return "***", nil
	}

	enc, err := crypto.NewAESGCMEncryptor(d.cfg.SecretKey, project, env)
	if err != nil {
		return "", err
	}
	plaintext, err := enc.Decrypt([]byte(item.Value), item.KeyID)
	if err != nil {
		return "", fmt.Errorf("decrypt secret: %w", err)
	}
	return string(plaintext), nil
}

func writeSecretGetOutput(w io.Writer, outputFormat string, item *store.Item, displayValue string) error {
	if outputFormat == formatJSON {
		out := map[string]interface{}{
			"key":        item.Key,
			keyValue:     displayValue,
			"version":    item.Version,
			"updated_at": item.UpdatedAt,
			"updated_by": item.UpdatedBy,
			"key_id":     item.KeyID,
		}
		return json.NewEncoder(w).Encode(out)
	}

	fmt.Fprintf(w, "key:        %s\n", item.Key)
	fmt.Fprintf(w, "value:      %s\n", displayValue)
	fmt.Fprintf(w, "version:    %d\n", item.Version)
	fmt.Fprintf(w, "updated_at: %s\n", item.UpdatedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(w, "updated_by: %s\n", item.UpdatedBy)
	fmt.Fprintf(w, "key_id:     %s\n", item.KeyID)
	return nil
}
