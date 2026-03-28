package cmd

import "github.com/spf13/cobra"

func newSecretCmd(d *deps, gf *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage encrypted secret values",
	}
	cmd.AddCommand(
		newSecretGetCmd(d, gf),
		newSecretSetCmd(d, gf),
		newSecretListCmd(d, gf),
		newSecretDeleteCmd(d, gf),
	)
	return cmd
}
