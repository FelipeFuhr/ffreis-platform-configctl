package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// requireProjectEnv returns an error if project or env is empty.
func requireProjectEnv(project, env string) error {
	if project == "" {
		return errors.New("--project is required")
	}
	if env == "" {
		return errors.New("--env is required")
	}
	return nil
}

// addProjectEnvFlags registers --project and --env persistent flags on cmd.
func addProjectEnvFlags(cmd *cobra.Command, project, env *string) {
	cmd.Flags().StringVar(project, flagProject, "", "Project name (required)")
	cmd.Flags().StringVar(env, flagEnv, "", "Environment name, e.g. dev, staging, prod (required)")
	_ = cmd.MarkFlagRequired(flagProject)
	_ = cmd.MarkFlagRequired(flagEnv)
}
