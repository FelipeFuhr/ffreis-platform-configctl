package validate_test

import (
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/internal/validate"
	"github.com/FelipeFuhr/ffreis-platform-configctl/pkg/store"
)

// TestMaxLengthRule_ExactlyAtMaxPasses closes the boundary gap between
// TestMaxLengthRulePass (value shorter than Max) and TestMaxLengthRuleFail
// (value longer than Max): MaxLengthRule.Check uses a strict `>` comparison,
// so a value whose length is EXACTLY Max must pass. Neither existing test
// exercises this exact boundary, which is precisely the value a mutation
// test flips first (`>` -> `>=`).
func TestMaxLengthRule_ExactlyAtMaxPasses(t *testing.T) {
	t.Parallel()

	rule := validate.MaxLengthRule{Max: 5}
	item := &store.Item{Key: "k", Value: "12345", Encrypted: false} // len == 5, the boundary itself
	if err := rule.Check(item); err != nil {
		t.Errorf("Check() with len(Value)==Max: error = %v, want nil", err)
	}
}
