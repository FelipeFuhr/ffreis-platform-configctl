package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfilesFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write profiles file: %v", err)
	}
	return path
}

func TestResolve_ReturnsNamedProfile(t *testing.T) {
	t.Parallel()

	path := writeProfilesFile(t, `
payments-prod:
  table: platform-config
  project: payments
  env: prod
  region: us-east-1
payments-dev:
  table: platform-config
  project: payments
  env: dev
`)

	got, err := Resolve(path, "payments-prod")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	want := Profile{Table: "platform-config", Project: "payments", Env: "prod", Region: "us-east-1"}
	if *got != want {
		t.Fatalf("Resolve() = %#v, want %#v", *got, want)
	}
}

func TestResolve_MissingFileIsClearError(t *testing.T) {
	t.Parallel()

	_, err := Resolve(filepath.Join(t.TempDir(), "does-not-exist.yaml"), "anything")
	if err == nil {
		t.Fatal("Resolve() error = nil, want error for missing file")
	}
}

func TestResolve_MissingNameIsClearError(t *testing.T) {
	t.Parallel()

	path := writeProfilesFile(t, "payments-prod:\n  table: platform-config\n")

	_, err := Resolve(path, "does-not-exist")
	if err == nil {
		t.Fatal("Resolve() error = nil, want error for undefined profile name")
	}
}

func TestLoad_InvalidYAMLIsError(t *testing.T) {
	t.Parallel()

	path := writeProfilesFile(t, "not: valid: yaml: [")

	if _, err := Load(path); err == nil {
		t.Fatal("Load() error = nil, want parse error")
	}
}

func TestDefaultPath_UnderConfigDir(t *testing.T) {
	t.Setenv("HOME", "/home/tester")

	got, err := DefaultPath("configctl")
	if err != nil {
		t.Fatalf("DefaultPath() error = %v", err)
	}
	want := "/home/tester/.config/configctl/profiles.yaml"
	if got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

// TestDefaultPath_GeneralizedPerApp proves the path is per-app, not
// hardcoded to configctl: vaultctl gets its own profiles file, under its own
// name, from the exact same loading code.
func TestDefaultPath_GeneralizedPerApp(t *testing.T) {
	t.Setenv("HOME", "/home/tester")

	got, err := DefaultPath("vaultctl")
	if err != nil {
		t.Fatalf("DefaultPath() error = %v", err)
	}
	want := "/home/tester/.config/vaultctl/profiles.yaml"
	if got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestDefaultPath_EmptyAppNameIsError(t *testing.T) {
	t.Parallel()

	if _, err := DefaultPath(""); err == nil {
		t.Fatal("DefaultPath(\"\") error = nil, want error")
	}
}
