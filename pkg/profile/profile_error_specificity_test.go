package profile

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestResolve_MissingFileErrorIsSpecific strengthens
// TestResolve_MissingFileIsClearError, which only ever checked `err != nil`
// — a check that would pass identically whether the file was missing, the
// YAML was malformed, or the profile name didn't exist. This asserts the
// error is SPECIFICALLY the "file not found" message (matching Load's
// os.IsNotExist branch), and specifically NOT the two other error shapes,
// so a regression that swapped in the wrong error path would be caught.
func TestResolve_MissingFileErrorIsSpecific(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "does-not-exist.yaml")
	_, err := Resolve(path, "anything")
	if err == nil {
		t.Fatal("Resolve() error = nil, want error for missing file")
	}
	if !strings.Contains(err.Error(), "not found at") {
		t.Fatalf(`Resolve() error = %q, want it to contain "not found at" (the missing-file path, not a YAML-parse or missing-name error)`, err.Error())
	}
	if strings.Contains(err.Error(), "parse profiles file") {
		t.Fatalf("Resolve() error = %q, misclassified as a YAML parse error", err.Error())
	}
}

// TestResolve_MissingNameErrorIsSpecific strengthens
// TestResolve_MissingNameIsClearError the same way: the file DOES exist and
// parses fine, so the error must specifically name the missing profile, not
// be confused with a file-read or parse failure.
func TestResolve_MissingNameErrorIsSpecific(t *testing.T) {
	t.Parallel()

	path := writeProfilesFile(t, "payments-prod:\n  table: platform-config\n")

	_, err := Resolve(path, "does-not-exist")
	if err == nil {
		t.Fatal("Resolve() error = nil, want error for undefined profile name")
	}
	if !strings.Contains(err.Error(), `"does-not-exist"`) || !strings.Contains(err.Error(), "not found in") {
		t.Fatalf(`Resolve() error = %q, want it to name the missing profile ("does-not-exist" ... "not found in" ...)`, err.Error())
	}
	if strings.Contains(err.Error(), "not found at") {
		t.Fatalf("Resolve() error = %q, misclassified as a missing-file error (the file exists)", err.Error())
	}
}

// TestLoad_InvalidYAMLErrorIsSpecific strengthens TestLoad_InvalidYAMLIsError
// the same way: the file exists (so it must not be misreported as missing)
// and the failure is specifically a parse error.
func TestLoad_InvalidYAMLErrorIsSpecific(t *testing.T) {
	t.Parallel()

	path := writeProfilesFile(t, "not: valid: yaml: [")

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want parse error")
	}
	if !strings.Contains(err.Error(), "parse profiles file") {
		t.Fatalf(`Load() error = %q, want it to contain "parse profiles file"`, err.Error())
	}
	if strings.Contains(err.Error(), "not found at") {
		t.Fatalf("Load() error = %q, misclassified as a missing-file error (the file exists, its content is just invalid)", err.Error())
	}
}
