package cmd

import "github.com/spf13/cobra"

func newConfigCmd(d *deps, gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage plaintext configuration values",
	}
	cmd.AddCommand(
		newConfigGetCmd(d, gf),
		newConfigSetCmd(d, gf),
		newConfigListCmd(d, gf),
		newConfigDeleteCmd(d, gf),
	)
	return cmd
}
