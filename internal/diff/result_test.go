package diff_test

import (
	"testing"

	"github.com/FelipeFuhr/ffreis-platform-configctl/internal/diff"
)

// TestResult_All_OrdersAndConcatenatesEveryKind exercises Result.All, which
// no other test in this package ever called — diff_test.go only ever
// inspects the Added/Modified/Deleted/Unchanged slices directly via
// HasChanges or by reading the fields. All's documented contract is a
// specific concatenation order (Added, Modified, Deleted, Unchanged); this
// pins that order and the total count.
func TestResult_All_OrdersAndConcatenatesEveryKind(t *testing.T) {
	t.Parallel()

	added := diff.Change{Kind: diff.Added, Key: "a"}
	modified := diff.Change{Kind: diff.Modified, Key: "m"}
	deleted := diff.Change{Kind: diff.Deleted, Key: "d"}
	unchanged := diff.Change{Kind: diff.Unchanged, Key: "u"}

	r := &diff.Result{
		Added:     []diff.Change{added},
		Modified:  []diff.Change{modified},
		Deleted:   []diff.Change{deleted},
		Unchanged: []diff.Change{unchanged},
	}

	all := r.All()
	if len(all) != 4 {
		t.Fatalf("All() returned %d changes, want 4", len(all))
	}
	wantOrder := []string{"a", "m", "d", "u"}
	for i, want := range wantOrder {
		if all[i].Key != want {
			t.Errorf("All()[%d].Key = %q, want %q (order must be Added, Modified, Deleted, Unchanged)", i, all[i].Key, want)
		}
	}
}

// TestResult_All_EmptyResult confirms All on a zero-value Result returns an
// empty (not nil-panicking) slice — the capacity-hint arithmetic in All's
// make() call (len(Added)+len(Modified)+len(Deleted)+len(Unchanged)) was
// never exercised by any test, since nothing ever called All() at all.
func TestResult_All_EmptyResult(t *testing.T) {
	t.Parallel()

	r := &diff.Result{}
	all := r.All()
	if len(all) != 0 {
		t.Fatalf("All() on empty Result = %v, want empty slice", all)
	}
}

// TestResult_All_SingleKindDominates covers the realistic, lopsided shapes a
// real diff commonly produces — everything Added (a fresh environment
// against a populated backup), everything Modified (a config-wide value
// bump, nothing added/removed), everything Deleted, or nothing changed at
// all but Unchanged — rather than only ever testing one-of-each. Each case
// also has the useful side effect of actually exercising All's capacity-hint
// sum (len(Added)+len(Modified)+len(Deleted)+len(Unchanged)) with one term
// dominating the other three; a one-of-each Result can never do that, since
// every term is equal and small.
func TestResult_All_SingleKindDominates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		kind diff.ChangeKind
		r    *diff.Result
	}{
		{"all added", diff.Added, &diff.Result{Added: manyChanges(diff.Added, 5)}},
		{"all modified", diff.Modified, &diff.Result{Modified: manyChanges(diff.Modified, 5)}},
		{"all deleted", diff.Deleted, &diff.Result{Deleted: manyChanges(diff.Deleted, 5)}},
		{"all unchanged", diff.Unchanged, &diff.Result{Unchanged: manyChanges(diff.Unchanged, 5)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			all := tc.r.All()
			if len(all) != 5 {
				t.Fatalf("All() = %d changes, want 5", len(all))
			}
			for i, c := range all {
				if c.Kind != tc.kind {
					t.Errorf("All()[%d].Kind = %q, want %q", i, c.Kind, tc.kind)
				}
			}
		})
	}
}

func manyChanges(kind diff.ChangeKind, n int) []diff.Change {
	out := make([]diff.Change, n)
	for i := range out {
		out[i] = diff.Change{Kind: kind, Key: string(rune('a' + i))}
	}
	return out
}
