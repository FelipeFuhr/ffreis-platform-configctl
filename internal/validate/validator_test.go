package validate_test

import (
	"testing"

	"github.com/ffreis/platform-configctl/internal/store"
	"github.com/ffreis/platform-configctl/internal/validate"
)

const (
	regexDigitsOnly = `^\d+$`
)

func cfg(key, value string) *store.Item {
	return &store.Item{
		Key:   key,
		Value: value,
		Type:  store.ItemTypeConfig,
	}
}

func TestDefaultSchemaPassesNonEmpty(t *testing.T) {
	v := validate.NewValidator()
	items := []*store.Item{
		cfg("host", "localhost"),
		cfg("port", "5432"),
	}
	schema := validate.DefaultSchema()
	errs := v.Validate(items, schema)
	if len(errs) != 0 {
		t.Errorf("expected 0 errors, got %d: %v", len(errs), errs)
	}
}

func TestDefaultSchemaFailsEmptyValue(t *testing.T) {
	v := validate.NewValidator()
	items := []*store.Item{cfg("host", "")}
	schema := validate.DefaultSchema()
	errs := v.Validate(items, schema)
	if len(errs) != 1 {
		t.Errorf("expected 1 error for empty value, got %d", len(errs))
	}
}

func TestRegexRulePass(t *testing.T) {
	rule, err := validate.NewRegexRule(regexDigitsOnly)
	if err != nil {
		t.Fatalf("NewRegexRule: %v", err)
	}
	item := cfg("port", "5432")
	if err := rule.Check(item); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRegexRuleFail(t *testing.T) {
	rule, err := validate.NewRegexRule(regexDigitsOnly)
	if err != nil {
		t.Fatalf("NewRegexRule: %v", err)
	}
	item := cfg("port", "not-a-number")
	if err := rule.Check(item); err == nil {
		t.Error("expected error for non-numeric value")
	}
}

func TestMaxLengthRulePass(t *testing.T) {
	rule := validate.MaxLengthRule{Max: 10}
	item := cfg("k", "short")
	if err := rule.Check(item); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMaxLengthRuleFail(t *testing.T) {
	rule := validate.MaxLengthRule{Max: 3}
	item := cfg("k", "toolong")
	if err := rule.Check(item); err == nil {
		t.Error("expected error for value exceeding max length")
	}
}

func TestValidateRequiredKeys(t *testing.T) {
	items := []*store.Item{cfg("present", "v")}
	errs := validate.ValidateRequiredKeys(items, []string{"present", "missing"})
	if len(errs) != 1 {
		t.Errorf("expected 1 error for missing required key, got %d", len(errs))
	}
	if errs[0].Key != "missing" {
		t.Errorf("expected key=missing, got %s", errs[0].Key)
	}
}

func TestEncryptedValueSkipsNonEmptyRule(t *testing.T) {
	// Encrypted items have empty-looking plaintext — rule must not fire.
	v := validate.NewValidator()
	items := []*store.Item{
		{Key: "secret", Value: "", Type: store.ItemTypeConfig, Encrypted: true},
	}
	schema := validate.DefaultSchema()
	errs := v.Validate(items, schema)
	if len(errs) != 0 {
		t.Errorf("encrypted item should skip non-empty-value rule, got %d errors", len(errs))
	}
}
