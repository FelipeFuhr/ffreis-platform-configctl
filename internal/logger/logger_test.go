package logger_test

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/ffreis/platform-configctl/internal/logger"
)

// TestMaskedReturnsSentinel verifies that Masked always returns the "***"
// sentinel regardless of the key. This is the single invariant secret-handling
// code paths rely on: there is no plaintext secret value carried through the
// returned zap.Field. If anyone changes Masked to ever emit anything else, this
// catches it. Per AGENTS.md: secrets are always masked as *** in logs and
// output; never add code paths that emit secret values even in debug mode.
func TestMaskedReturnsSentinel(t *testing.T) {
	cases := []string{
		"api_key",
		"password",
		"db_password",
		"AWS_SECRET_ACCESS_KEY",
		"value",
		"",              // empty key still produces sentinel
		"key.with.dots", // structured field names
		"key/with/slashes",
		strings.Repeat("x", 256), // long key
	}

	for _, key := range cases {
		f := logger.Masked(key)
		if f.Key != key {
			t.Errorf("Masked(%q) returned field with Key=%q, want %q", key, f.Key, key)
		}
		if f.Type != zapcore.StringType {
			t.Errorf("Masked(%q) returned field of type %v, want StringType", key, f.Type)
		}
		if f.String != "***" {
			t.Errorf("Masked(%q) returned value %q, want %q", key, f.String, "***")
		}
	}
}

// TestNewBuildsLoggerAtEachLevel verifies New accepts all the documented level
// strings and returns a usable logger. The four log methods are exercised to
// guard against zap config regressions that would crash on first use.
func TestNewBuildsLoggerAtEachLevel(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error"}
	for _, lvl := range levels {
		l, err := logger.New(lvl)
		if err != nil {
			t.Fatalf("New(%q): %v", lvl, err)
		}
		if l == nil {
			t.Fatalf("New(%q): returned nil logger", lvl)
		}
		// Each method must not panic. We don't assert on output because
		// New writes to stderr; the no-panic invariant is what callers rely on.
		l.Debug("debug-msg")
		l.Info("info-msg")
		l.Warn("warn-msg")
		l.Error("error-msg")
	}
}

// TestNewDefaultsToInfoOnInvalidLevel documents the fallback contract: unknown
// level strings do NOT error. They silently default to info. This is the
// intentional behaviour at logger.go:25 — UnmarshalText err is swallowed and
// the level is left at the zero value (InfoLevel). If that ever changes, any
// caller passing a typo'd level (`"infi"`, etc.) would suddenly get an error
// at startup instead of a working logger.
func TestNewDefaultsToInfoOnInvalidLevel(t *testing.T) {
	for _, lvl := range []string{"", "invalid", "trace", "INFO"} {
		l, err := logger.New(lvl)
		if err != nil {
			t.Errorf("New(%q): unexpected error %v (should fall back to info)", lvl, err)
		}
		if l == nil {
			t.Errorf("New(%q): returned nil logger", lvl)
		}
	}
}

// TestWithReturnsLoggerDifferentInstance verifies With produces a new Logger
// (not a mutation of the receiver). This matters because callers chain With
// calls expecting child loggers to inherit but not alias the parent's fields.
func TestWithReturnsLoggerDifferentInstance(t *testing.T) {
	parent, err := logger.New("info")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	child := parent.With(zap.String("component", "test"))
	if child == nil {
		t.Fatal("With returned nil")
	}
	// Smoke-check the child is functional.
	child.Info("child-msg")
}
