package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/logger"
	"github.com/ffreis/platform-configctl/internal/store"
	"github.com/ffreis/platform-configctl/internal/validate"
)

func newValidateCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate all config items against built-in or custom rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runValidate(cmd.Context(), d.store, d.log, validateOpts{project: project, env: env, outputFormat: gf.output}, os.Stdout, os.Stderr)
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}

type validateJSONErr struct {
	Key  string `json:"key"`
	Rule string `json:"rule"`
	Msg  string `json:"msg"`
}

type validateOpts struct {
	project      string
	env          string
	outputFormat string
}

func runValidate(
	ctx context.Context,
	st store.Store,
	log logger.Logger,
	opts validateOpts,
	stdout, stderr io.Writer,
) error {
	if err := requireProjectEnv(opts.project, opts.env); err != nil {
		return err
	}

	items, err := st.List(ctx, opts.project, opts.env, store.ItemTypeConfig)
	if err != nil {
		return fmt.Errorf("list configs: %w", err)
	}

	errs := validate.NewValidator().Validate(items, validate.DefaultSchema())
	if len(errs) == 0 {
		log.Info("validation passed", zap.Int("items", len(items)))
		return nil
	}

	log.Warn("validation failed", zap.Int("violations", len(errs)))

	if opts.outputFormat == formatJSON {
		if err := writeValidationErrorsJSON(stdout, errs); err != nil {
			return err
		}
	} else {
		writeValidationErrorsText(stderr, errs)
	}
	return fmt.Errorf("validation failed with %d violation(s)", len(errs))
}

func writeValidationErrorsJSON(w io.Writer, errs []validate.ValidationError) error {
	out := make([]validateJSONErr, 0, len(errs))
	for _, e := range errs {
		out = append(out, validateJSONErr{Key: e.Key, Rule: e.Rule, Msg: e.Msg})
	}
	return json.NewEncoder(w).Encode(out)
}

func writeValidationErrorsText(w io.Writer, errs []validate.ValidationError) {
	for _, e := range errs {
		fmt.Fprintf(w, "FAIL key=%s rule=%s: %s\n", e.Key, e.Rule, e.Msg)
	}
}
