package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/backup"
)

func newBackupImportCmd(d *deps, gf *globalFlags) *cobra.Command {
	var input string
	var dryRun, overwrite bool

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a backup file into DynamoDB",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" {
				return fmt.Errorf("--input is required")
			}

			if _, err := os.Stat(input); os.IsNotExist(err) {
				return fmt.Errorf("input file not found: %s", input)
			}

			importer := backup.NewImporter(d.store)
			result, err := importer.ImportFromFile(cmd.Context(), input, backup.ImportOptions{
				DryRun:    dryRun,
				Overwrite: overwrite,
				UpdatedBy: callerIdentity(cmd.Context(), d),
			})
			if err != nil {
				return fmt.Errorf("import: %w", err)
			}

			if dryRun {
				d.log.Info("dry-run complete",
					zap.Int("would-write", result.Written),
					zap.Int("skipped", result.Skipped),
				)
				return nil
			}

			d.log.Info("import complete",
				zap.Int("written", result.Written),
				zap.Int("skipped", result.Skipped),
				zap.Int("failed", result.Failed),
			)

			if result.Failed > 0 {
				for _, e := range result.Errors {
					d.log.Error("item failed", zap.Error(e))
				}
				return fmt.Errorf("%d items failed to import", result.Failed)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&input, "input", "", "Path to backup JSON file (required)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate and diff without writing")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Overwrite items regardless of stored version")
	_ = gf
	return cmd
}
