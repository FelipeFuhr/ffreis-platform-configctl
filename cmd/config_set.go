package cmd

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/store"
)

func newConfigSetCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a configuration value (idempotent)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			// Check whether the item already exists to determine version.
			existing, err := d.store.Get(cmd.Context(), project, env, store.ItemTypeConfig, key)
			if err != nil && err != store.ErrNotFound {
				return fmt.Errorf("get existing: %w", err)
			}

			var version int64
			var createdAt time.Time
			if existing != nil {
				// Idempotent: if value is unchanged, skip the write.
				if existing.Value == value {
					d.log.Info("no change, skipping write",
						zap.String(keyProject, project),
						zap.String("env", env),
						zap.String("key", key),
					)
					return nil
				}
				version = existing.Version
				createdAt = existing.CreatedAt
			}

			h := sha256.Sum256([]byte(value))
			item := &store.Item{
				Project:   project,
				Env:       env,
				Key:       key,
				Value:     value,
				Type:      store.ItemTypeConfig,
				Encrypted: false,
				Version:   version,
				Checksum:  fmt.Sprintf(checksumFormatSHA256, h),
				CreatedAt: createdAt,
				UpdatedBy: callerIdentity(cmd.Context(), d),
			}

			if err := d.store.Set(cmd.Context(), item); err != nil {
				return fmt.Errorf("set config: %w", err)
			}

			d.log.Info("config set",
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
