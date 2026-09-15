package guard

import (
	"errors"
	"testing"
)

// TestValidateSecretValue_RefusesEmptyAndDash is the package-level proof of
// the two incident-driven guards: a value that is empty/whitespace-only (a
// write that "succeeds" but stores garbage, undetected because presence
// checks pass on an empty string), and a value that is exactly "-" (a
// different but related "looks empty/garbage but technically succeeded"
// class — a stdin-placeholder byte stored as if it were the real secret).
// Both callers (platform-configctl's `secret set` and vaultctl's `put`) rely
// on this single function; if this guard is ever removed or weakened, this
// test fails first.
func TestValidateSecretValue_RefusesEmptyAndDash(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{"empty", "", ErrEmptyValue},
		{"whitespace only", "   ", ErrEmptyValue},
		{"whitespace with tabs and newline", "\t \n", ErrEmptyValue},
		{"bare dash", "-", ErrPlaceholderDash},
		{"dash with surrounding whitespace", "  -  ", ErrPlaceholderDash},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateSecretValue([]byte(tc.raw))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateSecretValue(%q) error = %v, want %v", tc.raw, err, tc.wantErr)
			}
		})
	}
}

func TestValidateSecretValue_AcceptsRealValues(t *testing.T) {
	t.Parallel()

	cases := []string{
		"sk_live_abc123",
		"a",
		"--", // two dashes is not the single-dash placeholder
		"-a",
		" -a",
		"value with spaces",
	}
	for _, raw := range cases {
		if err := ValidateSecretValue([]byte(raw)); err != nil {
			t.Errorf("ValidateSecretValue(%q) error = %v, want nil", raw, err)
		}
	}
}

func TestFingerprint_StableAndDistinguishing(t *testing.T) {
	t.Parallel()

	a := Fingerprint([]byte("value-one"))
	b := Fingerprint([]byte("value-two"))
	if a == b {
		t.Fatalf("Fingerprint produced the same digest %q for two different plaintexts", a)
	}
	if len(a) != 16 || len(b) != 16 {
		t.Fatalf("Fingerprint length = %d/%d, want 16 hex chars (8 bytes)", len(a), len(b))
	}

	again := Fingerprint([]byte("value-one"))
	if again != a {
		t.Fatalf("Fingerprint is not stable: %q != %q", again, a)
	}
}

func TestEnvTruthy(t *testing.T) {
	const name = "GUARD_TEST_TRUTHY"

	truthy := []string{"1", "true", "TRUE", "yes", "YES", "y", "on", "ON"}
	for _, v := range truthy {
		t.Setenv(name, v)
		if !EnvTruthy(name) {
			t.Errorf("EnvTruthy(%q) = false, want true", v)
		}
	}

	falsy := []string{"", "0", "false", "no", "n", "off", "garbage"}
	for _, v := range falsy {
		t.Setenv(name, v)
		if EnvTruthy(name) {
			t.Errorf("EnvTruthy(%q) = true, want false", v)
		}
	}
}
