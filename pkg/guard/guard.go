// Package guard holds small leak-control and input-safety primitives shared
// by platform-configctl and vaultctl. Neither binary imports the other's
// package, so any check both need to apply identically — "is this plaintext
// safe to fingerprint", "is this kill-switch env var set", "is this stdin
// value garbage rather than a real secret" — lives here once instead of
// being reimplemented (and risking drift) in each cmd tree.
package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
)

// ErrEmptyValue is returned when a secret value is empty or, after trimming
// surrounding whitespace, contains nothing at all.
var ErrEmptyValue = errors.New("secret value must not be empty or whitespace-only")

// ErrPlaceholderDash is returned when a secret value is exactly "-" once
// surrounding whitespace is trimmed. This is a distinct, deliberately named
// case (not folded into ErrEmptyValue) because a bare "-" is not obviously
// empty — it is the literal byte a caller's shell piped through, almost
// always because a command meant to feed a value via stdin was instead
// invoked in a way that treated "-" as a filename/stdin placeholder (e.g. a
// `--body -` style flag used incorrectly) and that placeholder itself got
// written as the "secret".
var ErrPlaceholderDash = errors.New(`secret value must not be the literal string "-"`)

// ValidateSecretValue refuses to accept raw as a real secret value when it is
// empty, whitespace-only, or exactly "-" after trimming. Both are real
// incidents this guard exists to prevent: a write that "succeeds" but stores
// garbage, silently, because presence checks alone pass on an empty or
// placeholder string. Validation trims only for the purpose of this check —
// callers keep storing raw exactly as read.
func ValidateSecretValue(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ErrEmptyValue
	}
	if trimmed == "-" {
		return ErrPlaceholderDash
	}
	return nil
}

// Fingerprint returns a short, one-way identifier for plaintext: the first 8
// bytes of sha256(plaintext), hex-encoded (16 hex characters). It is
// intentionally one-way and truncated — safe to print, log, or paste into a
// ticket, since it never reveals the value and is not intended to be
// collision-resistant against a targeted search of the full keyspace, only
// to let an operator confirm two secrets are (or are not) the same value.
func Fingerprint(plaintext []byte) string {
	sum := sha256.Sum256(plaintext)
	return hex.EncodeToString(sum[:8])
}

// EnvTruthy reports whether the named environment variable is set to a
// recognisably "on" value (1, t, true, yes, y, on — case-insensitive).
// Anything else, including unset or empty, is false. Shared by
// CONFIGCTL_NO_REVEAL and VAULTCTL_NO_REVEAL — same parsing rule, two
// independent switches (see each binary's own constant for the env var name).
func EnvTruthy(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if v == "" {
		return false
	}
	if b, err := strconv.ParseBool(v); err == nil {
		return b
	}
	switch v {
	case "yes", "y", "on":
		return true
	default:
		return false
	}
}
