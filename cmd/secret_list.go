package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

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
				return json.NewEncoder(os.Stdout).Encode(out)
			case "table":
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "KEY\tKEY_ID\tVERSION\tUPDATED_AT")
				for _, item := range items {
					fmt.Fprintf(w, "%s\t%s\t%d\t%s\n",
						item.Key, item.KeyID, item.Version,
						item.UpdatedAt.Format("2006-01-02T15:04:05Z"))
				}
				return w.Flush()
			default:
				for _, item := range items {
					fmt.Fprintf(os.Stdout, "%s=***\n", item.Key)
				}
			}
			return nil
		},
	}

	addProjectEnvFlags(cmd, &project, &env)
	return cmd
}
