package validate

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/ffreis/platform-configctl/internal/store"
)

// Rule is a validation constraint applied to a single item.
type Rule interface {
	// Name returns a human-readable rule identifier.
	Name() string
	// Check returns an error describing why the item fails the rule, or nil.
	Check(item *store.Item) error
}

// Schema maps item keys to the rules that apply to them.
// A key of "*" applies rules to every item.
type Schema struct {
	Rules map[string][]Rule
}

// ValidationError describes a single rule violation.
type ValidationError struct {
	Key  string
	Rule string
	Msg  string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("key=%s rule=%s: %s", e.Key, e.Rule, e.Msg)
}

// Validator applies a Schema to a slice of Items.
type Validator struct{}

// NewValidator constructs a Validator.
func NewValidator() *Validator { return &Validator{} }

// Validate applies all rules in schema to items and returns all violations.
func (v *Validator) Validate(items []*store.Item, schema *Schema) []ValidationError {
	var errs []ValidationError
	for _, item := range items {
		v.applyItemRules(&errs, item, schema)
	}
	return errs
}

func (v *Validator) applyItemRules(errs *[]ValidationError, item *store.Item, schema *Schema) {
	// Apply wildcard rules.
	v.applyRules(errs, item, schema.Rules["*"])
	// Apply key-specific rules.
	v.applyRules(errs, item, schema.Rules[item.Key])
}

func (v *Validator) applyRules(errs *[]ValidationError, item *store.Item, rules []Rule) {
	for _, r := range rules {
		if err := r.Check(item); err != nil {
			*errs = append(*errs, ValidationError{Key: item.Key, Rule: r.Name(), Msg: err.Error()})
		}
	}
}

// DefaultSchema returns a minimal schema that enforces non-empty keys and values.
func DefaultSchema() *Schema {
	return &Schema{
		Rules: map[string][]Rule{
			"*": {NonEmptyValueRule{}},
		},
	}
}

// --- built-in rules ---

// NonEmptyValueRule rejects items with empty plaintext values.
type NonEmptyValueRule struct{}

func (NonEmptyValueRule) Name() string { return "non-empty-value" }
func (NonEmptyValueRule) Check(item *store.Item) error {
	if !item.Encrypted && item.Value == "" {
		return errors.New("value must not be empty")
	}
	return nil
}

// RegexRule validates that a value matches a regular expression.
type RegexRule struct {
	Pattern string
	re      *regexp.Regexp
}

// NewRegexRule compiles pattern and returns an error if it is invalid.
func NewRegexRule(pattern string) (*RegexRule, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}
	return &RegexRule{Pattern: pattern, re: re}, nil
}

func (r *RegexRule) Name() string { return "regex:" + r.Pattern }
func (r *RegexRule) Check(item *store.Item) error {
	if item.Encrypted {
		return nil // cannot validate encrypted values
	}
	if !r.re.MatchString(item.Value) {
		return fmt.Errorf("value does not match pattern %q", r.Pattern)
	}
	return nil
}

// MaxLengthRule rejects values exceeding a byte length.
type MaxLengthRule struct{ Max int }

func (r MaxLengthRule) Name() string { return fmt.Sprintf("max-length:%d", r.Max) }
func (r MaxLengthRule) Check(item *store.Item) error {
	if item.Encrypted {
		return nil
	}
	if len(item.Value) > r.Max {
		return fmt.Errorf("value length %d exceeds maximum %d", len(item.Value), r.Max)
	}
	return nil
}

// RequiredKeysRule checks that specific keys are present in the item slice.
// This rule operates at the set level and is applied separately.
func ValidateRequiredKeys(items []*store.Item, required []string) []ValidationError {
	present := make(map[string]bool, len(items))
	for _, item := range items {
		present[item.Key] = true
	}
	var errs []ValidationError
	for _, k := range required {
		if !present[k] {
			errs = append(errs, ValidationError{Key: k, Rule: "required", Msg: "key is required but not present"})
		}
	}
	return errs
}
