package diff

import "github.com/ffreis/platform-configctl/internal/store"

// ChangeKind describes the nature of a difference between live state and snapshot.
type ChangeKind string

const (
	// Added means the item is in the snapshot but not live.
	Added ChangeKind = "added"
	// Modified means the item exists in both but values differ.
	Modified ChangeKind = "modified"
	// Deleted means the item is live but not in the snapshot.
	Deleted ChangeKind = "deleted"
	// Unchanged means both sides are identical.
	Unchanged ChangeKind = "unchanged"
)

// Change represents a single diffed entry.
type Change struct {
	Kind     ChangeKind
	Key      string
	ItemType store.ItemType
	OldValue string // live value; empty for Added
	NewValue string // snapshot value; empty for Deleted
}

// Result holds the output of a diff operation grouped by change kind.
type Result struct {
	Added     []Change
	Modified  []Change
	Deleted   []Change
	Unchanged []Change
}

// HasChanges returns true if there is any difference between the two sides.
func (r *Result) HasChanges() bool {
	return len(r.Added) > 0 || len(r.Modified) > 0 || len(r.Deleted) > 0
}

// All returns every Change regardless of kind, ordered: Added, Modified,
// Deleted, Unchanged.
func (r *Result) All() []Change {
	out := make([]Change, 0, len(r.Added)+len(r.Modified)+len(r.Deleted)+len(r.Unchanged))
	out = append(out, r.Added...)
	out = append(out, r.Modified...)
	out = append(out, r.Deleted...)
	out = append(out, r.Unchanged...)
	return out
}
