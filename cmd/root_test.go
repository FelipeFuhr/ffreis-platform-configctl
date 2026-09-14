package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ffreis/platform-configctl/internal/appconfig"
	"github.com/ffreis/platform-configctl/internal/profile"
)

func TestBuildRoot_HasSubcommandsAndFlags(t *testing.T) {
	t.Parallel()

	root := buildRoot()
	if root.Use != "platform-configctl" {
		t.Fatalf("Use = %q, want platform-configctl", root.Use)
	}

	want := map[string]bool{
		"config": false, "secret": false, "backup": false,
		"diff": false, "validate": false, "whoami": false, "version": false,
	}
	for _, c := range root.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}

	for _, name := range []string{"region", "table", "log-level", "output", "ui", "profile"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("persistent flag --%s is not registered", name)
		}
	}
}

func TestExecute_Help(t *testing.T) {
	t.Parallel()

	// buildRoot()+Execute("--help") never reaches PersistentPreRunE (Cobra
	// short-circuits help), so this is safe without AWS credentials.
	root := buildRoot()
	root.SetArgs([]string{"--help"})
	var out bytes.Buffer
	root.SetOut(&out)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(--help) error = %v", err)
	}
	if out.Len() == 0 {
		t.Fatal("--help produced no output")
	}
}

func TestNewWhoamiCmd(t *testing.T) {
	t.Parallel()

	d := &deps{cfg: &appconfig.Config{}}
	cmd := newWhoamiCmd(d)
	if cmd.Use != "whoami" {
		t.Fatalf("Use = %q, want whoami", cmd.Use)
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	// No AWS credentials in the test environment: callerIdentity degrades to "unknown".
	if out.String() != "unknown\n" {
		t.Fatalf("output = %q, want %q", out.String(), "unknown\n")
	}
}

func TestNewVersionCmd_DefaultsWhenUnset(t *testing.T) {
	t.Parallel()

	gf := &globalFlags{output: "text"}
	d := &deps{}
	cmd := newVersionCmd(gf, d)
	if cmd.Use != "version" {
		t.Fatalf("Use = %q, want version", cmd.Use)
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	want := "dev (commit=unknown built=unknown)\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestNewVersionCmd_JSON(t *testing.T) {
	t.Parallel()

	gf := &globalFlags{output: formatJSON}
	d := &deps{}
	cmd := newVersionCmd(gf, d)

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["version"] != "dev" || got["commit"] != "unknown" || got["build_time"] != "unknown" {
		t.Fatalf("got = %#v, unexpected", got)
	}
}

func TestNewVersionCmd_SkipsPersistentPreRun(t *testing.T) {
	t.Parallel()

	// version must run without AWS credentials or CONFIGCTL_TABLE — it
	// overrides PersistentPreRunE with a no-op specifically for this reason.
	cmd := newVersionCmd(&globalFlags{output: "text"}, &deps{})
	if cmd.PersistentPreRunE == nil {
		t.Fatal("PersistentPreRunE is nil, want an override no-op")
	}
	if err := cmd.PersistentPreRunE(cmd, nil); err != nil {
		t.Fatalf("PersistentPreRunE() error = %v, want nil", err)
	}
}

func TestInitDeps_MissingTableNoFlagOverride(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "")
	gf := &globalFlags{}
	d := &deps{}
	err := initDeps(context.Background(), gf, d)
	if err != appconfig.ErrMissingTable {
		t.Fatalf("initDeps() error = %v, want %v", err, appconfig.ErrMissingTable)
	}
}

func TestInitDeps_InvalidUIMode(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "")
	gf := &globalFlags{table: "tbl-override", ui: "not-a-real-mode"}
	d := &deps{}
	err := initDeps(context.Background(), gf, d)
	if err == nil {
		t.Fatal("initDeps() error = nil, want error for invalid --ui mode")
	}
}

func TestInitDeps_SucceedsWithFlagOverrides(t *testing.T) {
	// logger.New never errors on an unrecognised level (defaults to info),
	// and config.LoadDefaultConfig/dynamodb.NewFromConfig don't validate
	// credentials at construction time, so this succeeds without real AWS
	// access — exercising the full happy path (presenter, logger, AWS
	// config, store construction) deterministically.
	t.Setenv("CONFIGCTL_TABLE", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_REGION", "")
	gf := &globalFlags{table: "tbl-override", region: "us-east-1", ui: "plain", logLevel: "debug"}
	d := &deps{}
	if err := initDeps(context.Background(), gf, d); err != nil {
		t.Fatalf("initDeps() error = %v, want nil", err)
	}
	if d.cfg == nil || d.cfg.TableName != "tbl-override" {
		t.Fatalf("d.cfg = %#v, want TableName=tbl-override", d.cfg)
	}
	if d.cfg.AWSRegion != "us-east-1" {
		t.Fatalf("d.cfg.AWSRegion = %q, want us-east-1", d.cfg.AWSRegion)
	}
	if d.log == nil {
		t.Fatal("d.log is nil")
	}
	if d.store == nil {
		t.Fatal("d.store is nil")
	}
	if d.ui == nil {
		t.Fatal("d.ui is nil")
	}
}

// writeProfilesFile writes a profiles.yaml under a fresh $HOME (set via
// t.Setenv) so profile.DefaultPath() resolves to it deterministically.
func writeProfilesFile(t *testing.T, contents string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "configctl")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir profiles dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "profiles.yaml"), []byte(contents), 0o600); err != nil {
		t.Fatalf("write profiles.yaml: %v", err)
	}
}

func TestInitDeps_ProfileSuppliesTableRegionProjectEnv(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_REGION", "")
	writeProfilesFile(t, "payments-prod:\n  table: platform-config\n  project: payments\n  env: prod\n  region: us-east-1\n")

	gf := &globalFlags{profile: "payments-prod", ui: "plain"}
	d := &deps{}
	if err := initDeps(context.Background(), gf, d); err != nil {
		t.Fatalf("initDeps() error = %v, want nil", err)
	}
	if d.cfg.TableName != "platform-config" {
		t.Fatalf("cfg.TableName = %q, want platform-config", d.cfg.TableName)
	}
	if d.cfg.AWSRegion != "us-east-1" {
		t.Fatalf("cfg.AWSRegion = %q, want us-east-1", d.cfg.AWSRegion)
	}
	if d.profile == nil || d.profile.Project != "payments" || d.profile.Env != "prod" {
		t.Fatalf("d.profile = %#v, want Project=payments Env=prod", d.profile)
	}
}

func TestInitDeps_ExplicitFlagsOverrideProfile(t *testing.T) {
	t.Setenv("CONFIGCTL_TABLE", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_REGION", "")
	writeProfilesFile(t, "payments-prod:\n  table: platform-config\n  region: us-east-1\n")

	gf := &globalFlags{profile: "payments-prod", table: "override-table", region: "eu-west-1", ui: "plain"}
	d := &deps{}
	if err := initDeps(context.Background(), gf, d); err != nil {
		t.Fatalf("initDeps() error = %v, want nil", err)
	}
	if d.cfg.TableName != "override-table" {
		t.Fatalf("cfg.TableName = %q, want override-table (explicit flag must win)", d.cfg.TableName)
	}
	if d.cfg.AWSRegion != "eu-west-1" {
		t.Fatalf("cfg.AWSRegion = %q, want eu-west-1 (explicit flag must win)", d.cfg.AWSRegion)
	}
}

func TestInitDeps_ProfileMissingFileIsClearError(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.config/configctl/profiles.yaml written
	gf := &globalFlags{profile: "anything"}
	d := &deps{}
	if err := initDeps(context.Background(), gf, d); err == nil {
		t.Fatal("initDeps() error = nil, want error for missing profiles file")
	}
}

func TestInitDeps_ProfileNameNotFoundIsClearError(t *testing.T) {
	writeProfilesFile(t, "payments-prod:\n  table: platform-config\n")
	gf := &globalFlags{profile: "does-not-exist"}
	d := &deps{}
	if err := initDeps(context.Background(), gf, d); err == nil {
		t.Fatal("initDeps() error = nil, want error for undefined profile name")
	}
}

func TestApplyProfileProjectEnv_ExplicitFlagWinsOverProfile(t *testing.T) {
	t.Parallel()

	d := &deps{profile: &profile.Profile{Project: "from-profile", Env: "from-profile-env"}}
	project, env := "explicit-project", ""
	applyProfileProjectEnv(d, &project, &env)
	if project != "explicit-project" {
		t.Fatalf("project = %q, want explicit-project unchanged", project)
	}
	if env != "from-profile-env" {
		t.Fatalf("env = %q, want from-profile-env (filled from profile)", env)
	}
}

func TestApplyProfileProjectEnv_NilProfileIsNoop(t *testing.T) {
	t.Parallel()

	project, env := "", ""
	applyProfileProjectEnv(&deps{}, &project, &env)
	if project != "" || env != "" {
		t.Fatalf("project/env = %q/%q, want unchanged when no profile is active", project, env)
	}
}

func TestCallerIdentity_NoCredentialsReturnsUnknown(t *testing.T) {
	t.Parallel()

	// With no AWS credentials configured in the test environment, this must
	// degrade gracefully to "unknown" rather than propagate an error.
	got := callerIdentity(context.Background(), &deps{cfg: &appconfig.Config{}})
	if got != "unknown" {
		t.Fatalf("callerIdentity() = %q, want %q (or this environment unexpectedly has AWS credentials)", got, "unknown")
	}
}
