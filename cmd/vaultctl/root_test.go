package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ffreis/platform-configctl/internal/profile"
)

func TestBuildRoot_HasSubcommandsAndFlags(t *testing.T) {
	t.Parallel()

	root := buildRoot()
	if root.Use != "vaultctl" {
		t.Fatalf("Use = %q, want vaultctl", root.Use)
	}

	want := map[string]bool{
		"get": false, "put": false, "exec": false, "export-env": false,
		"list": false, "delete": false, "backup": false, "whoami": false,
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

	for _, name := range []string{"region", "log-level", "profile"} {
		if root.PersistentFlags().Lookup(name) == nil {
			t.Errorf("persistent flag --%s is not registered", name)
		}
	}
	// vaultctl deliberately has no --table and no --project: tier+env alone
	// resolve the table, and this vault has no per-project dimension.
	for _, name := range []string{"table", "project"} {
		if root.PersistentFlags().Lookup(name) != nil {
			t.Errorf("persistent flag --%s should not exist on vaultctl", name)
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

func TestEveryTierCommand_RequiresEnvFlag(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"get", "identity", "k"},
		{"put", "identity", "k"},
		{"list", "identity"},
		{"delete", "identity", "k"},
	} {
		root := buildRoot()
		root.SetArgs(args)
		var out, errOut bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errOut)
		if err := root.Execute(); err == nil {
			t.Errorf("Execute(%v) error = nil, want error for missing required --env", args)
		}
	}
}

func TestResolveProfile_EmptyNameIsNoop(t *testing.T) {
	t.Parallel()

	got, err := resolveProfile("")
	if err != nil {
		t.Fatalf("resolveProfile(\"\") error = %v", err)
	}
	if got != nil {
		t.Fatalf("resolveProfile(\"\") = %#v, want nil", got)
	}
}

func TestResolveProfile_UsesVaultctlOwnPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".config", "vaultctl")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte("prod-west:\n  region: us-west-2\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := resolveProfile("prod-west")
	if err != nil {
		t.Fatalf("resolveProfile() error = %v", err)
	}
	if got.Region != "us-west-2" {
		t.Fatalf("resolveProfile().Region = %q, want us-west-2", got.Region)
	}
}

func TestResolveProfile_DoesNotReadConfigctlsProfilesFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// A configctl profile of the same name exists — vaultctl must not see it.
	configctlDir := filepath.Join(home, ".config", "configctl")
	if err := os.MkdirAll(configctlDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configctlDir, "profiles.yaml"),
		[]byte("shared-name:\n  region: eu-west-1\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := resolveProfile("shared-name"); err == nil {
		t.Fatal("resolveProfile() error = nil, want error — vaultctl must not resolve configctl's own profiles file")
	}
}

func TestApplyProfileRegion_OnlyFillsEmptyRegion(t *testing.T) {
	t.Parallel()

	prof := &profile.Profile{Region: "us-east-1"}

	region := ""
	applyProfileRegion(prof, &region)
	if region != "us-east-1" {
		t.Errorf("applyProfileRegion() region = %q, want us-east-1", region)
	}

	explicit := "eu-central-1"
	applyProfileRegion(prof, &explicit)
	if explicit != "eu-central-1" {
		t.Errorf("applyProfileRegion() overwrote an explicit region: got %q, want eu-central-1", explicit)
	}
}

func TestApplyProfileRegion_NilProfileIsNoop(t *testing.T) {
	t.Parallel()

	region := "explicit"
	applyProfileRegion(nil, &region)
	if region != "explicit" {
		t.Errorf("applyProfileRegion(nil) mutated region: got %q", region)
	}
}

func TestRequireSecretKey(t *testing.T) {
	t.Parallel()

	if err := requireSecretKey(""); err == nil {
		t.Error("requireSecretKey(\"\") error = nil, want error")
	}
	if err := requireSecretKey("k"); err != nil {
		t.Errorf("requireSecretKey(\"k\") error = %v, want nil", err)
	}
}

func TestExitCodeForError(t *testing.T) {
	t.Parallel()

	if got := exitCodeForError(&ExitError{Code: exitNotFound}); got != exitNotFound {
		t.Errorf("exitCodeForError(ExitError{2}) = %d, want %d", got, exitNotFound)
	}
	if got := exitCodeForError(nil); got != exitError {
		t.Errorf("exitCodeForError(nil) = %d, want %d", got, exitError)
	}
}
