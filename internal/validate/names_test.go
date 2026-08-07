package validate_test

import (
	"testing"

	"github.com/ffreis/platform-configctl/internal/validate"
)

func TestValidationError_Error(t *testing.T) {
	t.Parallel()

	e := &validate.ValidationError{Key: "k", Rule: "r", Msg: "m"}
	want := "key=k rule=r: m"
	if got := e.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestRegexRule_Name(t *testing.T) {
	t.Parallel()

	rule, err := validate.NewRegexRule(regexDigitsOnly)
	if err != nil {
		t.Fatalf("NewRegexRule: %v", err)
	}
	want := "regex:" + regexDigitsOnly
	if got := rule.Name(); got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
}

func TestMaxLengthRule_Name(t *testing.T) {
	t.Parallel()

	rule := validate.MaxLengthRule{Max: 10}
	if got := rule.Name(); got != "max-length:10" {
		t.Fatalf("Name() = %q, want max-length:10", got)
	}
}
