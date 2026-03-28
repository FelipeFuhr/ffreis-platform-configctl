package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/store"
)

func newSecretDeleteCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "delete <key>",
		Short: "Delete a secret (idempotent)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			_, err := d.store.Get(cmd.Context(), project, env, store.ItemTypeSecret, key)
			if err == store.ErrNotFound {
				d.log.Warn("secret not found, nothing deleted",
					zap.String(keyProject, project),
					zap.String("env", env),
					zap.String("key", key),
				)
				return nil
			}
			if err != nil {
				return fmt.Errorf("get secret: %w", err)
			}

			if err := d.store.Delete(cmd.Context(), project, env, store.ItemTypeSecret, key); err != nil {
				return fmt.Errorf("delete secret: %w", err)
			}

			d.log.Info("secret deleted",
				zap.String(keyProject, project),
				zap.String("env", env),
				zap.String("key", key),
			)
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	_ = gf
	return cmd
}
