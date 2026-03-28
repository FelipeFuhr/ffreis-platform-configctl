package validate

import (
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
)

// FuzzRegexRule exercises regex pattern compilation and value matching.
//
// Invariants verified:
//   - NewRegexRule must never panic (returns error for invalid patterns)
//   - RegexRule.Check must never panic for any item value
//   - A valid compiled rule applied to any value must not panic
func FuzzRegexRule(f *testing.F) {
	// Seed: representative patterns and values
	f.Add("^[a-z]+$", "hello")
	f.Add("^[a-z]+$", "HELLO") // non-matching
	f.Add(`^\d{4}-\d{2}-\d{2}$`, "2024-01-15")
	f.Add(`^\d{4}-\d{2}-\d{2}$`, "not-a-date")
	f.Add(".*", "any value")
	f.Add("", "anything")
	f.Add(`^(foo|bar|baz)$`, "foo")
	f.Add(`^arn:aws:[a-z0-9]+:[a-z0-9-]*:\d{12}:.+$`, "arn:aws:iam::123456789012:role/MyRole")
	// ReDoS-style patterns (must not cause catastrophic backtracking)
	f.Add(`(a+)+b`, "aaaaaaaaaaaaaaaaac")
	f.Add(`([a-zA-Z]+)*`, "aaaaaaaaaaaaaaaaaac")

	f.Fuzz(func(t *testing.T, pattern, value string) {
		rule, err := NewRegexRule(pattern)
		if err != nil {
			// Invalid pattern: compile error is acceptable, must not panic
			return
		}
		item := &store.Item{Key: "fuzz-key", Value: value}
		// Must not panic regardless of value
		_ = rule.Check(item)
	})
}

// FuzzValidatorWithArbitraryItems exercises the Validator with arbitrary
// item key/value combinations against the default schema.
//
// Invariants verified:
//   - Validate must never panic for any combination of item fields
//   - Encrypted items must never fail the non-empty-value rule
func FuzzValidatorWithArbitraryItems(f *testing.F) {
	f.Add("my-key", "my-value", false)
	f.Add("", "", false)
	f.Add("secret-key", "", true) // encrypted: should pass non-empty check
	f.Add("*", "wildcard", false) // key matching wildcard in schema
	f.Add("key", "value", true)
	f.Add("\x00", "\x00", false) // null bytes

	v := NewValidator()
	schema := DefaultSchema()

	f.Fuzz(func(t *testing.T, key, value string, encrypted bool) {
		item := &store.Item{
			Key:       key,
			Value:     value,
			Encrypted: encrypted,
		}

		errs := v.Validate([]*store.Item{item}, schema)

		// Encrypted items must always pass the non-empty-value rule
		if encrypted {
			for _, e := range errs {
				if e.Rule == "non-empty-value" {
					t.Fatalf("encrypted item failed non-empty-value rule (must be skipped): %v", e)
				}
			}
		}
	})
}
