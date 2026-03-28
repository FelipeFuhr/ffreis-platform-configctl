package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
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
			key := args[0]
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}
			if err := d.cfg.RequireSecretKey(); err != nil {
				return err
			}

			item, err := d.store.Get(cmd.Context(), project, env, store.ItemTypeSecret, key)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					d.log.Warn("secret not found", zap.String("key", key))
					os.Exit(2)
				}
				return fmt.Errorf("get secret: %w", err)
			}

			displayValue := "***"
			if reveal {
				enc, err := crypto.NewAESGCMEncryptor(d.cfg.SecretKey, project, env)
				if err != nil {
					return err
				}
				plaintext, err := enc.Decrypt([]byte(item.Value), item.KeyID)
				if err != nil {
					return fmt.Errorf("decrypt secret: %w", err)
				}
				displayValue = string(plaintext)
			}

			switch gf.output {
			case formatJSON:
				out := map[string]interface{}{
					"key":        item.Key,
					keyValue:     displayValue,
					"version":    item.Version,
					"updated_at": item.UpdatedAt,
					"updated_by": item.UpdatedBy,
					"key_id":     item.KeyID,
				}
				return json.NewEncoder(os.Stdout).Encode(out)
			default:
				fmt.Fprintf(os.Stdout, "key:        %s\n", item.Key)
				fmt.Fprintf(os.Stdout, "value:      %s\n", displayValue)
				fmt.Fprintf(os.Stdout, "version:    %d\n", item.Version)
				fmt.Fprintf(os.Stdout, "updated_at: %s\n", item.UpdatedAt.Format("2006-01-02T15:04:05Z"))
				fmt.Fprintf(os.Stdout, "updated_by: %s\n", item.UpdatedBy)
				fmt.Fprintf(os.Stdout, "key_id:     %s\n", item.KeyID)
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().BoolVar(&reveal, "reveal", false, "Decrypt and print the plaintext value")
	return cmd
}
