package cmd

import (
	"errors"
	"os"
	"strconv"
	"strings"

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

// addProjectEnvFlags registers --project and --env flags on cmd.
//
// Neither flag is marked required on the flag itself: an active --profile
// (see initDeps and applyProfileProjectEnv) can supply either as a default,
// so presence is instead enforced by the explicit requireProjectEnv call
// every command already makes after PreRunE has had a chance to apply that
// fallback. An explicitly-passed --project/--env always wins over the
// profile.
func addProjectEnvFlags(cmd *cobra.Command, d *deps, project, env *string) {
	cmd.Flags().StringVar(project, flagProject, "", "Project name (required unless supplied by --profile)")
	cmd.Flags().StringVar(env, flagEnv, "", "Environment name, e.g. dev, staging, prod (required unless supplied by --profile)")

	cmd.PreRunE = func(*cobra.Command, []string) error {
		applyProfileProjectEnv(d, project, env)
		return nil
	}
}

// applyProfileProjectEnv fills project/env from the active --profile, if
// any, but only for values the caller left empty.
func applyProfileProjectEnv(d *deps, project, env *string) {
	if d == nil || d.profile == nil {
		return
	}
	if *project == "" && d.profile.Project != "" {
		*project = d.profile.Project
	}
	if *env == "" && d.profile.Env != "" {
		*env = d.profile.Env
	}
}

// isEnvTruthy reports whether the named environment variable is set to a
// recognisably "on" value (1, t, true, yes, y, on — case-insensitive).
// Anything else, including unset or empty, is false.
func isEnvTruthy(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if v == "" {
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	switch v {
	case "yes", "y", "on":
		return true
	default:
		return false
	}
}
