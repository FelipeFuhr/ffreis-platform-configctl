package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ffreis/platform-configctl/internal/store"
)

func newSecretListCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secret keys (values are always masked)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			items, err := d.store.List(cmd.Context(), project, env, store.ItemTypeSecret)
			if err != nil {
				return fmt.Errorf("list secrets: %w", err)
			}

			switch gf.output {
			case formatJSON:
				out := make([]map[string]interface{}, 0, len(items))
				for _, item := range items {
					out = append(out, map[string]interface{}{
						"key":        item.Key,
						keyValue:     "***",
						"key_id":     item.KeyID,
						"version":    item.Version,
						"updated_at": item.UpdatedAt,
						"updated_by": item.UpdatedBy,
					})
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
			case "table":
				rows := make([][]string, 0, len(items))
				for _, item := range items {
					rows = append(rows, []string{
						item.Key,
						item.KeyID,
						fmt.Sprintf("%d", item.Version),
						item.UpdatedAt.Format("2006-01-02T15:04:05Z"),
					})
				}
				return newCommandOutput(cmd, d.ui).Table([]string{"KEY", "KEY_ID", "VERSION", "UPDATED_AT"}, rows)
			default:
				out := newCommandOutput(cmd, d.ui)
				for _, item := range items {
					out.Line(item.Key + "=***")
				}
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}
