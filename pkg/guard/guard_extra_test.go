package guard

import (
	"errors"
	"testing"
)

// TestValidateSecretValue_WhitespaceVariants extends
// TestValidateSecretValue_RefusesEmptyAndDash's whitespace cases beyond a
// single space and a mixed tab+newline: pure tabs, pure newlines, and a
// dash embedded in non-space whitespace (a dash surrounded by tabs/newlines
// rather than spaces). All must be refused via the same two error paths as
// plain-space whitespace.
func TestValidateSecretValue_WhitespaceVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{"tabs only", "\t\t\t", ErrEmptyValue},
		{"newlines only", "\n\n\n", ErrEmptyValue},
		{"carriage returns only", "\r\r", ErrEmptyValue},
		{"dash surrounded by tabs and newlines", "\t-\n", ErrPlaceholderDash},
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

// TestValidateSecretValue_UnicodeDashLookalikesAreAccepted documents (and
// locks in) a deliberate boundary of ValidateSecretValue: it guards against
// the specific ASCII hyphen-minus "-" byte that shells emit for a
// stdin-placeholder convention (e.g. `--body -`), not against anything that
// merely looks like a dash to a human. A Unicode em dash or en dash is a
// plausible (if unusual) real secret character and must be accepted, not
// silently rejected by an over-broad match. If ValidateSecretValue is ever
// changed to normalise Unicode dashes before comparing, this test is the
// one that should be revisited, not deleted.
func TestValidateSecretValue_UnicodeDashLookalikesAreAccepted(t *testing.T) {
	t.Parallel()

	emDash := string([]rune{0x2014})
	enDash := string([]rune{0x2013})
	cases := []string{
		emDash,
		enDash,
		"prefix" + emDash,
	}
	for _, raw := range cases {
		if err := ValidateSecretValue([]byte(raw)); err != nil {
			t.Errorf("ValidateSecretValue(%q) error = %v, want nil (Unicode dash lookalikes are not the ASCII placeholder)", raw, err)
		}
	}
}

// TestEnvTruthy_PaddedAndMixedCase closes two gaps in TestEnvTruthy's
// hand-picked lists: a value with surrounding whitespace (as would arrive
// from a shell export with accidental padding) and mixed-case falsy values
// (TestEnvTruthy only ever exercises mixed-case on the TRUTHY side via
// "TRUE"/"YES"/"ON"; "False" was never tried).
func TestEnvTruthy_PaddedAndMixedCase(t *testing.T) {
	const name = "GUARD_TEST_TRUTHY_EXTRA"

	t.Setenv(name, "  true  ")
	if !EnvTruthy(name) {
		t.Error(`EnvTruthy("  true  ") = false, want true (surrounding whitespace must be trimmed)`)
	}

	t.Setenv(name, "False")
	if EnvTruthy(name) {
		t.Error(`EnvTruthy("False") = true, want false (mixed-case falsy)`)
	}

	t.Setenv(name, "  ")
	if EnvTruthy(name) {
		t.Error(`EnvTruthy("  ") = true, want false (whitespace-only must behave like unset)`)
	}
}

// TestFingerprint_OneBitFlipChangesDigest is a loose avalanche check:
// SHA-256 is a cryptographic hash so single-bit changes are expected to
// change essentially every output bit, but
// TestFingerprint_StableAndDistinguishing only ever compares two UNRELATED
// strings ("value-one" vs "value-two"), which differ in many bytes. This
// test isolates the smallest possible change (one bit) and confirms the
// truncated fingerprint still differs.
func TestFingerprint_OneBitFlipChangesDigest(t *testing.T) {
	t.Parallel()

	base := []byte("a-representative-secret-value-01")
	flipped := make([]byte, len(base))
	copy(flipped, base)
	flipped[0] ^= 0x01 // flip the lowest bit of the first byte only

	a := Fingerprint(base)
	b := Fingerprint(flipped)
	if a == b {
		t.Fatalf("Fingerprint produced identical digests for a one-bit-different input: %q", a)
	}
}
