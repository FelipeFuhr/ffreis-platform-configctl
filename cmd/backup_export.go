package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/backup"
)

func newBackupExportCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env, output string
	var includeSecrets bool

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export configuration (and optionally secrets) to a JSON backup file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			if includeSecrets {
				if err := d.cfg.RequireSecretKey(); err != nil {
					return err
				}
			}

			toolVersion := "dev"
			exporter := backup.NewExporter(d.store)
			bf, err := exporter.Export(cmd.Context(), project, env, backup.ExportOptions{
				IncludeSecrets: includeSecrets,
				ToolVersion:    toolVersion,
				ExportedBy:     callerIdentity(cmd.Context(), d),
			})
			if err != nil {
				return fmt.Errorf("export: %w", err)
			}

			raw, err := json.MarshalIndent(bf, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal backup: %w", err)
			}

			if output == "" || output == "-" {
				fmt.Fprintln(os.Stdout, string(raw))
			} else {
				if err := os.WriteFile(output, append(raw, '\n'), 0600); err != nil {
					return fmt.Errorf("write file %s: %w", output, err)
				}
				d.log.Info("backup exported",
					zap.String("file", output),
					zap.Int("items", bf.Metadata.ItemCount),
				)
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringVar(&output, "output", "-", "Output file path; use '-' for stdout")
	cmd.Flags().BoolVar(&includeSecrets, "include-secrets", false, "Include secrets as ciphertext in the backup")
	_ = gf
	return cmd
}
