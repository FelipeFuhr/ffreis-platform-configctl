package cmd

import (
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/profile"
)

// TestApplyProfileProjectEnv_FillsFromProfileWhenEmpty is the missing half
// of the profile-fill matrix: TestApplyProfileProjectEnv_ExplicitFlagWinsOverProfile
// only ever exercises the "profile has a value, but the caller already
// supplied one" branch (fill must NOT happen), and
// TestApplyProfileProjectEnv_NilProfileIsNoop only covers "no profile at
// all". Neither ever proves the actual fill happens when it SHOULD: caller
// left project empty, and the active profile DOES have a value. Mutating
// `d.profile.Project != ""` to `== ""` would leave *project unfilled in
// exactly this case, and nothing caught it.
func TestApplyProfileProjectEnv_FillsFromProfileWhenEmpty(t *testing.T) {
	t.Parallel()

	d := &deps{profile: &profile.Profile{Project: "from-profile", Env: "from-profile-env"}}
	project, env := "", ""
	applyProfileProjectEnv(d, &project, &env)
	if project != "from-profile" {
		t.Fatalf("project = %q, want %q (filled from the active profile)", project, "from-profile")
	}
	if env != "from-profile-env" {
		t.Fatalf("env = %q, want %q (filled from the active profile)", env, "from-profile-env")
	}
}

// TestExitError_NilReceiver_ErrorIsSafe proves ExitError.Error() does not
// panic on a nil *ExitError. This is not academic: (*ExitError).Error()
// starts with `if e == nil || e.Err == nil { return "" }`, an OR whose
// short-circuit is the ONLY thing standing between a nil-receiver call and
// a nil-pointer dereference on e.Err. Nothing previously called Error() on
// a nil *ExitError — every existing test constructs a populated one — so a
// mutation (or a future refactor) that broke that short-circuit would only
// ever be caught by an actual crash in production, not by this suite.
func TestExitError_NilReceiver_ErrorIsSafe(t *testing.T) {
	t.Parallel()

	var e *ExitError
	if got := e.Error(); got != "" {
		t.Fatalf("nil *ExitError.Error() = %q, want empty string (and, above all, must not panic)", got)
	}
}

// TestExitError_NilErrField_ErrorIsSafe covers the other half of that same
// guard: a non-nil *ExitError whose Err field is nil.
func TestExitError_NilErrField_ErrorIsSafe(t *testing.T) {
	t.Parallel()

	e := &ExitError{Code: 1}
	if got := e.Error(); got != "" {
		t.Fatalf("ExitError{Err: nil}.Error() = %q, want empty string", got)
	}
}
