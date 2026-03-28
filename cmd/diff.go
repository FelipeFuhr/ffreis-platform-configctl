package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
			return runDiff(cmd.Context(), d, gf, project, env, inputFile, os.Stdout)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringVar(&inputFile, "input", "", "Path to backup JSON file to compare against (required)")
	return cmd
}

func runDiff(ctx context.Context, d *deps, gf *globalFlags, project, env, inputFile string, stdout io.Writer) error {
	if inputFile == "" {
		return fmt.Errorf("--input is required")
	}
	if err := requireProjectEnv(project, env); err != nil {
		return err
	}

	bf, err := loadBackupFile(inputFile)
	if err != nil {
		return err
	}

	snapshot := snapshotItemsFromBackup(project, env, bf)
	live, err := loadLiveItems(ctx, d.store, project, env)
	if err != nil {
		return err
	}

	result := diff.New().Diff(live, snapshot)
	if !result.HasChanges() {
		d.log.Info("no differences found")
		return nil
	}

	d.log.Info("differences found",
		zap.Int("added", len(result.Added)),
		zap.Int("modified", len(result.Modified)),
		zap.Int("deleted", len(result.Deleted)),
	)
	return writeDiffOutput(stdout, gf.output, result)
}

func loadBackupFile(path string) (*backup.BackupFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var bf backup.BackupFile
	if err := json.Unmarshal(raw, &bf); err != nil {
		return nil, fmt.Errorf("parse backup: %w", err)
	}
	if err := bf.Verify(); err != nil {
		return nil, err
	}
	return &bf, nil
}

func snapshotItemsFromBackup(project, env string, bf *backup.BackupFile) []*store.Item {
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
	return snapshot
}

func loadLiveItems(ctx context.Context, st store.Store, project, env string) ([]*store.Item, error) {
	liveConfigs, err := st.List(ctx, project, env, store.ItemTypeConfig)
	if err != nil {
		return nil, fmt.Errorf("list live configs: %w", err)
	}
	liveSecrets, err := st.List(ctx, project, env, store.ItemTypeSecret)
	if err != nil {
		return nil, fmt.Errorf("list live secrets: %w", err)
	}
	return append(liveConfigs, liveSecrets...), nil
}

func writeDiffOutput(w io.Writer, outputFormat string, result *diff.Result) error {
	if outputFormat == formatJSON {
		return json.NewEncoder(w).Encode(result.All())
	}
	writeDiffText(w, result)
	return nil
}

func writeDiffText(w io.Writer, result *diff.Result) {
	for _, c := range result.Added {
		fmt.Fprintf(w, "+ [%s] %s = %s\n", c.ItemType, c.Key, c.NewValue)
	}
	for _, c := range result.Modified {
		fmt.Fprintf(w, "~ [%s] %s: %s → %s\n", c.ItemType, c.Key, c.OldValue, c.NewValue)
	}
	for _, c := range result.Deleted {
		fmt.Fprintf(w, "- [%s] %s = %s\n", c.ItemType, c.Key, c.OldValue)
	}
}
