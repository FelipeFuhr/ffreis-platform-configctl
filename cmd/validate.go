package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

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
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			items, err := d.store.List(cmd.Context(), project, env, store.ItemTypeConfig)
			if err != nil {
				return fmt.Errorf("list configs: %w", err)
			}

			schema := validate.DefaultSchema()
			v := validate.NewValidator()
			errs := v.Validate(items, schema)

			if len(errs) == 0 {
				d.log.Info("validation passed", zap.Int("items", len(items)))
				return nil
			}

			d.log.Warn("validation failed", zap.Int("violations", len(errs)))

			switch gf.output {
			case formatJSON:
				type jsonErr struct {
					Key  string `json:"key"`
					Rule string `json:"rule"`
					Msg  string `json:"msg"`
				}
				out := make([]jsonErr, 0, len(errs))
				for _, e := range errs {
					out = append(out, jsonErr{Key: e.Key, Rule: e.Rule, Msg: e.Msg})
				}
				if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
					return err
				}
			default:
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "FAIL key=%s rule=%s: %s\n", e.Key, e.Rule, e.Msg)
				}
			}
			return fmt.Errorf("validation failed with %d violation(s)", len(errs))
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}
