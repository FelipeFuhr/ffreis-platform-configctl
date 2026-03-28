package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/ffreis/platform-configctl/internal/store"
)

func newConfigListCmd(d *deps, gf *globalFlags) *cobra.Command {
	var project, env string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all configuration keys and values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireProjectEnv(project, env); err != nil {
				return err
			}

			items, err := d.store.List(cmd.Context(), project, env, store.ItemTypeConfig)
			if err != nil {
				return fmt.Errorf("list configs: %w", err)
			}

			switch gf.output {
			case formatJSON:
				out := make([]map[string]interface{}, 0, len(items))
				for _, item := range items {
					out = append(out, map[string]interface{}{
						"key":        item.Key,
						keyValue:     item.Value,
						"version":    item.Version,
						"updated_at": item.UpdatedAt,
						"updated_by": item.UpdatedBy,
					})
				}
				return json.NewEncoder(os.Stdout).Encode(out)
			case "table":
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "KEY\tVALUE\tVERSION\tUPDATED_AT")
				for _, item := range items {
					fmt.Fprintf(w, "%s\t%s\t%d\t%s\n",
						item.Key, item.Value, item.Version, item.UpdatedAt.Format("2006-01-02T15:04:05Z"))
				}
				return w.Flush()
			default: // text
				for _, item := range items {
					fmt.Fprintf(os.Stdout, "%s=%s\n", item.Key, item.Value)
				}
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}
