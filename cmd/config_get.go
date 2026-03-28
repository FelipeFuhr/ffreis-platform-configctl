package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/store"
)

func newConfigGetCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Get a configuration value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			item, err := d.store.Get(cmd.Context(), project, env, store.ItemTypeConfig, key)
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					d.log.Warn("key not found", zap.String("key", key))
					os.Exit(2)
				}
				return fmt.Errorf("get config: %w", err)
			}

			switch gf.output {
			case formatJSON:
				return json.NewEncoder(os.Stdout).Encode(map[string]string{keyValue: item.Value})
			default:
				fmt.Fprintln(os.Stdout, item.Value)
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}
