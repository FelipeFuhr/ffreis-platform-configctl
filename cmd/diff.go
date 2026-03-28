package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/backup"
	"github.com/ffreis/platform-configctl/internal/diff"
	"github.com/ffreis/platform-configctl/internal/store"
)

func newDiffCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env, inputFile string

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare live DynamoDB state against a backup snapshot",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("--input is required")
			}
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			// Load backup file.
			raw, err := os.ReadFile(inputFile)
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
			var bf backup.BackupFile
			if err := json.Unmarshal(raw, &bf); err != nil {
				return fmt.Errorf("parse backup: %w", err)
			}
			if err := bf.Verify(); err != nil {
				return err
			}

			// Build snapshot item slice.
			snapshot := make([]*store.Item, 0, len(bf.Items))
			for _, bi := range bf.Items {
				snapshot = append(snapshot, &store.Item{
					Key:       bi.Key,
					Project:   project,
					Env:       env,
					Value:     bi.Value,
					Type:      store.ItemType(bi.ItemType),
					Encrypted: bi.Encrypted,
					KeyID:     bi.KeyID,
					Version:   bi.Version,
				})
			}

			// Load live items.
			liveConfigs, err := d.store.List(cmd.Context(), project, env, store.ItemTypeConfig)
			if err != nil {
				return fmt.Errorf("list live configs: %w", err)
			}
			liveSecrets, err := d.store.List(cmd.Context(), project, env, store.ItemTypeSecret)
			if err != nil {
				return fmt.Errorf("list live secrets: %w", err)
			}
			live := append(liveConfigs, liveSecrets...)

			differ := diff.New()
			result := differ.Diff(live, snapshot)

			if !result.HasChanges() {
				d.log.Info("no differences found")
				return nil
			}

			d.log.Info("differences found",
				zap.Int("added", len(result.Added)),
				zap.Int("modified", len(result.Modified)),
				zap.Int("deleted", len(result.Deleted)),
			)

			switch gf.output {
			case formatJSON:
				return json.NewEncoder(os.Stdout).Encode(result.All())
			default:
				for _, c := range result.Added {
					fmt.Fprintf(os.Stdout, "+ [%s] %s = %s\n", c.ItemType, c.Key, c.NewValue)
				}
				for _, c := range result.Modified {
					fmt.Fprintf(os.Stdout, "~ [%s] %s: %s → %s\n", c.ItemType, c.Key, c.OldValue, c.NewValue)
				}
				for _, c := range result.Deleted {
					fmt.Fprintf(os.Stdout, "- [%s] %s = %s\n", c.ItemType, c.Key, c.OldValue)
				}
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringVar(&inputFile, "input", "", "Path to backup JSON file to compare against (required)")
	return cmd
}
