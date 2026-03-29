package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/appconfig"
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
			return runBackupExport(
				cmd.Context(),
				d,
				backupExportOpts{project: project, env: env, outputPath: output, includeSecrets: includeSecrets},
				os.Stdout,
				os.WriteFile,
				callerIdentity,
			)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	cmd.Flags().StringVar(&output, "output", "-", "Output file path; use '-' for stdout")
	cmd.Flags().BoolVar(&includeSecrets, "include-secrets", false, "Include secrets as ciphertext in the backup")
	_ = gf
	return cmd
}

type backupExportOpts struct {
	project        string
	env            string
	outputPath     string
	includeSecrets bool
}

func runBackupExport(
	ctx context.Context,
	d *deps,
	opts backupExportOpts,
	stdout io.Writer,
	writeFile func(string, []byte, os.FileMode) error,
	exportedBy func(context.Context, *deps) string,
) error {
	if err := requireProjectEnv(opts.project, opts.env); err != nil {
		return err
	}
	if err := requireSecretKeyIfNeeded(d.cfg, opts.includeSecrets); err != nil {
		return err
	}

	bf, err := exportBackupFile(ctx, d, opts.project, opts.env, opts.includeSecrets, exportedBy(ctx, d))
	if err != nil {
		return err
	}

	raw, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup: %w", err)
	}

	if isStdoutOutput(opts.outputPath) {
		fmt.Fprintln(stdout, string(raw))
		return nil
	}

	if err := writeFile(opts.outputPath, append(raw, '\n'), 0600); err != nil {
		return fmt.Errorf("write file %s: %w", opts.outputPath, err)
	}
	d.log.Info("backup exported",
		zap.String("file", opts.outputPath),
		zap.Int("items", bf.Metadata.ItemCount),
	)
	return nil
}

func requireSecretKeyIfNeeded(cfg *appconfig.Config, includeSecrets bool) error {
	if !includeSecrets {
		return nil
	}
	return cfg.RequireSecretKey()
}

func exportBackupFile(ctx context.Context, d *deps, project, env string, includeSecrets bool, exportedBy string) (*backup.BackupFile, error) {
	const toolVersion = "dev"
	exporter := backup.NewExporter(d.store)
	bf, err := exporter.Export(ctx, project, env, backup.ExportOptions{
		IncludeSecrets: includeSecrets,
		ToolVersion:    toolVersion,
		ExportedBy:     exportedBy,
	})
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	return bf, nil
}

func isStdoutOutput(outputPath string) bool {
	return outputPath == "" || outputPath == "-"
}
