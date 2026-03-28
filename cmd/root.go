// Package cmd implements the platform-configctl CLI using Cobra.
// All dependencies are injected; there are no global variables.
package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/logger"
	"github.com/ffreis/platform-configctl/internal/store"
)

// deps holds all resolved runtime dependencies. It is populated by the root
// command's PersistentPreRunE before any subcommand runs.
type deps struct {
	cfg   *appconfig.Config
	log   logger.Logger
	store store.Store
}

// globalFlags holds the values bound to top-level persistent flags.
type globalFlags struct {
	region   string
	table    string
	logLevel string
	output   string
}

// Execute is the entrypoint for the CLI. It builds the command tree and runs it.
func Execute() error {
	return buildRoot().Execute()
}

func buildRoot() *cobra.Command {
	gf := &globalFlags{}
	d := &deps{}

	root := &cobra.Command{
		Use:   "platform-configctl",
		Short: "Control plane for all platform configuration state",
		Long: `platform-configctl manages configuration and secrets for platform projects.

Config and secrets are stored in DynamoDB. Secrets are encrypted with AES-256-GCM.
Set CONFIGCTL_TABLE, AWS credentials, and CONFIGCTL_SECRET_KEY before use.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initDeps(cmd.Context(), gf, d)
		},
	}

	root.PersistentFlags().StringVar(&gf.region, "region", "", "AWS region (overrides AWS_DEFAULT_REGION)")
	root.PersistentFlags().StringVar(&gf.table, "table", "", "DynamoDB table name (overrides CONFIGCTL_TABLE)")
	root.PersistentFlags().StringVar(&gf.logLevel, "log-level", "", "Log level: debug, info, warn, error (overrides CONFIGCTL_LOG_LEVEL)")
	root.PersistentFlags().StringVar(&gf.output, "output", "text", "Output format: text, json, table")

	root.AddCommand(
		newConfigCmd(d, gf),
		newSecretCmd(d, gf),
		newBackupCmd(d, gf),
		newDiffCmd(d, gf),
		newValidateCmd(d, gf),
		newWhoamiCmd(d),
	)

	return root
}

// initDeps resolves all runtime dependencies. Called by PersistentPreRunE.
func initDeps(ctx context.Context, gf *globalFlags, d *deps) error {
	cfg, err := appconfig.Load()
	if err != nil {
		// Allow --table flag to satisfy the requirement.
		if gf.table == "" {
			return err
		}
		cfg = &appconfig.Config{
			TableName: gf.table,
			LogLevel:  "info",
		}
		// Reload from env for other fields.
		loaded, lerr := appconfig.Load()
		if lerr == nil {
			cfg = loaded
		}
	}

	// CLI flags override env vars.
	if gf.table != "" {
		cfg.TableName = gf.table
	}
	if gf.region != "" {
		cfg.AWSRegion = gf.region
	}
	if gf.logLevel != "" {
		cfg.LogLevel = gf.logLevel
	}

	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}

	// Build AWS config.
	awsOpts := []func(*config.LoadOptions) error{}
	if cfg.AWSRegion != "" {
		awsOpts = append(awsOpts, config.WithRegion(cfg.AWSRegion))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	dynamoClient := dynamodb.NewFromConfig(awsCfg)
	st := store.NewDynamoStore(dynamoClient, cfg.TableName)

	d.cfg = cfg
	d.log = log
	d.store = st

	log.Debug("dependencies initialised",
		zap.String("table", cfg.TableName),
		zap.String("region", cfg.AWSRegion),
	)
	return nil
}

// callerIdentity returns the IAM caller identity ARN for use as updated_by.
func callerIdentity(ctx context.Context, d *deps) string {
	cfg := d.cfg
	awsOpts := []func(*config.LoadOptions) error{}
	if cfg.AWSRegion != "" {
		awsOpts = append(awsOpts, config.WithRegion(cfg.AWSRegion))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, awsOpts...)
	if err != nil {
		return "unknown"
	}
	stsClient := sts.NewFromConfig(awsCfg)
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "unknown"
	}
	if out.Arn == nil {
		return "unknown"
	}
	return *out.Arn
}

// newWhoamiCmd prints the resolved IAM identity for diagnostics.
func newWhoamiCmd(d *deps) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Print the resolved IAM caller identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			arn := callerIdentity(cmd.Context(), d)
			fmt.Fprintln(os.Stdout, arn)
			return nil
		},
	}
}
