package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/store"
)

func newConfigDeleteCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "delete <key>",
		Short: "Delete a configuration key (idempotent)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			// Check existence first to provide informative logging.
			_, err := d.store.Get(cmd.Context(), project, env, store.ItemTypeConfig, key)
			if err == store.ErrNotFound {
				d.log.Warn("key not found, nothing deleted",
					zap.String(keyProject, project),
					zap.String("env", env),
					zap.String("key", key),
				)
				return nil
			}
			if err != nil {
				return fmt.Errorf("get config: %w", err)
			}

			if err := d.store.Delete(cmd.Context(), project, env, store.ItemTypeConfig, key); err != nil {
				return fmt.Errorf("delete config: %w", err)
			}

			d.log.Info("config deleted",
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
