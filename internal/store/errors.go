package store

import "errors"

// ErrNotFound is returned when an item does not exist in the store.
var ErrNotFound = errors.New("item not found")

// ErrVersionConflict is returned when a conditional write fails due to a
// concurrent modification.
type ErrVersionConflict struct {
	Key             string
	ExpectedVersion int64
	ActualVersion   int64
}

func (e *ErrVersionConflict) Error() string {
	return "version conflict on key " + e.Key +
		": run `diff` to inspect current state before retrying"
}
