package cmd

import "github.com/spf13/cobra"

func newBackupCmd(d *deps, gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Export and import configuration snapshots",
	}
	cmd.AddCommand(
		newBackupExportCmd(d, gf),
		newBackupImportCmd(d, gf),
	)
	return cmd
}
